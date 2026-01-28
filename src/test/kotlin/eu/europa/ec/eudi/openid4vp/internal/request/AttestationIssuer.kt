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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.net.URI
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.time.Duration.Companion.seconds

object AttestationIssuer {
    const val ID = "Attestation Issuer"
    private val algAndKey by lazy { randomKey() }
    private val attestationDuration = 10.seconds

    val verifier: JWSVerifier by lazy {
        val (alg, key) = algAndKey
        val h = JWSHeader.Builder(alg).build()
        DefaultJWSVerifierFactory().createJWSVerifier(h, key.toPublicKey())
    }

    fun attestation(
        clock: Clock,
        clientId: String,
        clientPubKey: JWK,
        redirectUris: List<URI>? = null,
        responseUris: List<URI>? = null,
    ): SignedJWT {
        val (alg, key) = algAndKey
        val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
        val header = JWSHeader.Builder(alg)
            .type(JOSEObjectType("verifier-attestation+jwt"))
            .build()
        val now = clock.instant()
        require(!clientPubKey.isPrivate) { "clientPubKey should be public" }
        val cnf = mapOf("jwk" to clientPubKey.toPublicJWK().toJSONObject())
        val claimSet = with(JWTClaimsSet.Builder()) {
            issuer(ID)
            subject(clientId)
            issueTime(now.toDate())
            expirationTime(expiration(now).toDate())
            claim("cnf", cnf)
            redirectUris?.let { uris -> claim("redirect_uris", uris.map { it.toString() }) }
            responseUris?.let { uris -> claim("response_urls", uris.map { it.toString() }) }
            build()
        }

        return SignedJWT(header, claimSet).apply { sign(signer) }
    }

    private fun expiration(iat: Instant) = iat.plusSeconds(attestationDuration.inWholeSeconds)

    private fun Instant.toDate() = Date.from(this)
}
