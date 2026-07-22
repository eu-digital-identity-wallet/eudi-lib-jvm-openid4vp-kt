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
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequestObject
import kotlinx.serialization.json.Json
import java.security.KeyStore
import java.util.*

internal fun UnvalidatedRequestObject.signed(
    jwkSet: JWKSet,
    typ: JOSEObjectType? = JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE),
): String {
    val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
    headerBuilder.keyID(jwkSet.keys[0].keyID)
    typ?.let {
        headerBuilder.type(it)
    }

    val signedJWT = SignedJWT(headerBuilder.build(), toJwtClaimSet())

    val signer = DefaultJWSSignerFactory().createJWSSigner(jwkSet.keys[0], JWSAlgorithm.RS256)
    signedJWT.sign(signer)

    return signedJWT.serialize()
}

internal fun UnvalidatedRequestObject.signWithKeystore(
    typ: JOSEObjectType? = JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE),
): String {
    val keyStore = KeyStore.getInstance("JKS")
    keyStore.load(
        load("certificates/certificates.jks"),
        "12345".toCharArray(),
    )

    val chain = keyStore.getCertificateChain("verifierexample")
    val base64EncodedChain = chain.map {
        com.nimbusds.jose.util.Base64.encode(it.encoded)
    }
    val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
    headerBuilder.x509CertChain(base64EncodedChain.toMutableList())
    typ.let {
        headerBuilder.type(it)
    }

    val signedJWT = SignedJWT(headerBuilder.build(), toJwtClaimSet())

    val jwkSet = JWKSet.load(keyStore) { _ -> "12345".toCharArray() }
    val signingKey = jwkSet.filter(
        JWKMatcher.Builder()
            .keyType(KeyType.RSA)
            .keyID("verifierexample")
            .build(),
    ).keys[0]

    val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey)
    signedJWT.sign(signer)

    return signedJWT.serialize()
}

private fun UnvalidatedRequestObject.toJwtClaimSet(): JWTClaimsSet {
    val json = Json.encodeToString(this)
    val claimSet = JWTClaimsSet.parse(json)
    return with(JWTClaimsSet.Builder(claimSet)) {
        audience("https://self-issued.me/v2")
        issueTime(Date())
        build()
    }
}
