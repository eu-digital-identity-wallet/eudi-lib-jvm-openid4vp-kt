/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.internal.Base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.DID
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.Signature
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.request.AttestationIssuer
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequestObject
import kotlinx.serialization.json.Json
import java.time.Clock

internal fun UnvalidatedRequestObject.multiSigned(
    signers: List<SchemeSigner>,
): ReceivedRequest.MultiSigned {
    require(signers.isNotEmpty()) { "At least one signer is required" }

    // Convert the request object to JWT claims
    val claimsSet = toJWTClaimSet()

    // Create the payload as Base64UrlNoPadding
    val payloadJson = claimsSet.toString()
    val payloadBase64 = base64UrlNoPadding.encode(payloadJson.encodeToByteArray())
    val payload = Base64UrlNoPadding.invoke(payloadBase64).getOrThrow()

    // Create signatures for each signer
    val signatures = signers.map { signer ->
        // Create a SignedJWT for this signer
        val header = with(JWSHeader.Builder(signer.alg)) {
            type(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
            signer.headerCustomization(this)
            build()
        }

        // Sign the JWT
        val jwt = SignedJWT(header, claimsSet).apply {
            val jwsSigner = DefaultJWSSignerFactory().createJWSSigner(signer.key, signer.alg)
            sign(jwsSigner)
        }

        // Extract the parts from the signed JWT
        val parts = jwt.serialize().split(".")
        val protectedHeader = Base64UrlNoPadding(parts[0]).getOrThrow()
        val signature = Base64UrlNoPadding(parts[2]).getOrThrow()

        // Create a Signature object
        Signature(protected = protectedHeader, signature = signature)
    }

    // Create a JwsJson.General object with the payload and signatures
    val jwsJson = JwsJson.General(payload = payload, signatures = signatures)

    // Return a ReceivedRequest.Signed with the JwsJson.General object
    return ReceivedRequest.MultiSigned(jwsJson)
}

class SchemeSigner(
    val alg: JWSAlgorithm,
    val key: JWK,
    val headerCustomization: (JWSHeader.Builder).() -> Unit,
)

internal fun didSigner(didAlgAndKey: Pair<JWSAlgorithm, ECKey>): SchemeSigner {
    val (alg2, key2) = didAlgAndKey
    val originalClientId = DID.parse("did:example:123").getOrThrow()
    val clientId = "decentralized_identifier:$originalClientId"
    return SchemeSigner(alg2, key2) {
        customParam("client_id", clientId)
        keyID("did:example:123#key-1")
    }
}

internal fun verifierAttestationSigner(didAlgAndKey: Pair<JWSAlgorithm, ECKey>, clock: Clock): SchemeSigner {
    val (alg, key) = didAlgAndKey
    val verifierAttestation = AttestationIssuer.attestation(
        clock = clock,
        clientId = "verifier_attestation:http://example.com",
        clientPubKey = key.toPublicJWK(),
    )
    return SchemeSigner(alg, key) {
        customParam("client_id", "verifier_attestation:http://www.example.com")
        customParam("jwt", verifierAttestation.serialize())
    }
}

internal fun UnvalidatedRequestObject.toJWTClaimSet(): JWTClaimsSet {
    val json = Json.encodeToString(this)
    return JWTClaimsSet.parse(json)
}
