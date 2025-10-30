/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.openid4vp.internal.response

import com.nimbusds.jose.*
import com.nimbusds.jose.JWEAlgorithm.Family
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.Jwt
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionSpecification
import kotlinx.serialization.json.*

/**
 * Creates according to the [verifier's requirements][ResponseEncryptionSpecification], an encrypted JWT which encapsulates
 * the provided [data]
 *
 * @param data the response to be sent to the verifier
 * @return the serialized encrypted JWT
 *
 * @throws JOSEException in case of an error
 */
@Throws(JOSEException::class)
internal fun ResponseEncryptionSpecification.encrypt(data: AuthorizationResponsePayload): Jwt {
    val header = jweHeader(encryptionAlgorithm, encryptionMethod, recipientKey, data)
    val claims = JwtPayloadFactory.encryptedJwtClaimSet(data)
    val encrypter = EncrypterFactory.createEncrypter(encryptionAlgorithm, recipientKey)
    val encryptedJwt = EncryptedJWT(header, claims).apply { encrypt(encrypter) }
    return encryptedJwt.serialize()
}

private fun jweHeader(
    jweAlgorithm: JWEAlgorithm,
    encryptionMethod: EncryptionMethod,
    recipientKey: JWK,
    data: AuthorizationResponsePayload,
    builderAction: JWEHeader.Builder.() -> Unit = {},
): JWEHeader {
    if (jweAlgorithm in Family.ECDH_ES) {
        require(data.encryptionParameters is EncryptionParameters.DiffieHellman) {
            "Diffie-Hellman encryption parameters are required for ${jweAlgorithm.name}"
        }
    }

    val (apv, apu) =
        when (val encryptionParameters = data.encryptionParameters) {
            is EncryptionParameters.DiffieHellman -> {
                val apv = data.nonce?.let { Base64URL.encode(it) }
                apv to encryptionParameters.apu
            }
            else -> null to null
        }

    return JWEHeader.Builder(jweAlgorithm, encryptionMethod)
        .apply {
            builderAction()
            apv?.let(::agreementPartyVInfo)
            apu?.let(::agreementPartyUInfo)
            keyID(recipientKey.keyID)
        }
        .build()
}

private object JwtPayloadFactory {

    private const val VP_TOKEN_CLAIM = "vp_token"
    private const val STATE_CLAIM = "state"
    private const val ERROR_CLAIM = "error"
    private const val ERROR_DESCRIPTION_CLAIM = "error_description"

    fun encryptedJwtClaimSet(data: AuthorizationResponsePayload): JWTClaimsSet =
        buildJsonObject {
            payloadClaims(data)
        }.asJWTClaimSet()

    private fun JsonObjectBuilder.payloadClaims(data: AuthorizationResponsePayload) {
        data.state?.let {
            put(STATE_CLAIM, it)
        }
        when (data) {
            is AuthorizationResponsePayload.Success -> {
                put(VP_TOKEN_CLAIM, data.verifiablePresentations.asJsonObject())
            }

            is AuthorizationResponsePayload.InvalidRequest -> {
                put(ERROR_CLAIM, AuthorizationRequestErrorCode.fromError(data.error).code)
                put(ERROR_DESCRIPTION_CLAIM, "${data.error}")
            }

            is AuthorizationResponsePayload.NoConsensusResponseData -> {
                put(ERROR_CLAIM, AuthorizationRequestErrorCode.ACCESS_DENIED.code)
            }
        }
    }

    private fun JsonObject.asJWTClaimSet(): JWTClaimsSet {
        val jsonStr = Json.encodeToString(this)
        return JWTClaimsSet.parse(jsonStr)
    }
}

internal object EncrypterFactory {

    fun createEncrypter(
        algorithm: JWEAlgorithm,
        recipientKey: JWK,
    ): JWEEncrypter =
        createEncrypterOrNull(algorithm, recipientKey)
            ?: error("Cannot find appropriate encryption key for ${algorithm.name}")

    fun createEncrypterOrNull(
        algorithm: JWEAlgorithm,
        recipientKey: JWK,
    ): JWEEncrypter? =
        familyOf(algorithm)?.let { family ->
            when {
                family == Family.ECDH_ES && recipientKey is ECKey -> ECDHEncrypter(recipientKey)
                family == Family.RSA && recipientKey is RSAKey -> RSAEncrypter(recipientKey)
                else -> null
            }
        }

    fun canBeUsed(algorithm: JWEAlgorithm, candidateRecipientKey: JWK): Boolean {
        return familyOf(algorithm)?.let { family ->
            when {
                family == Family.ECDH_ES && candidateRecipientKey is ECKey -> true
                family == Family.RSA && candidateRecipientKey is RSAKey -> true
                else -> false
            }
        } == true
    }

    private val SupportedFamilies = listOf(Family.ECDH_ES, Family.RSA)
    private fun familyOf(algorithm: JWEAlgorithm): Family? =
        SupportedFamilies.firstOrNull { family -> family.contains(algorithm) }
}
