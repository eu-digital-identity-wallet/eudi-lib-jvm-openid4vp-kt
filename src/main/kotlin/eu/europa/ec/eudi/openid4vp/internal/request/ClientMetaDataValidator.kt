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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.UnsupportedClientMetaData
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.response.EncrypterFactory
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.json.JsonObject
import java.text.ParseException

internal object ClientMetaDataValidator {

    @Throws(AuthorizationRequestException::class)
    fun validateClientMetaData(
        unvalidated: UnvalidatedClientMetaData,
        responseMode: ResponseMode,
        query: DCQL?,
        responseEncryptionConfiguration: ResponseEncryptionConfiguration,
        walletSupportedVpFormats: VpFormatsSupported,
    ): ValidatedClientMetaData {
        val verifierAdvertisedJwkSet = jwks(unvalidated)
        val verifierSupportedEncryptionMethods = responseEncryptionMethodsSupported(unvalidated)

        val responseEncryptionSpecification =
            if (!responseMode.requiresEncryption()) {
                ensure(null == verifierSupportedEncryptionMethods) {
                    RequestValidationError.InvalidClientMetaData(
                        "'${OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED}' must not be provided when encryption is not required",
                    ).asException()
                }
                null
            } else {
                ensureNotNull(verifierAdvertisedJwkSet) {
                    RequestValidationError.InvalidClientMetaData(
                        "'${OpenId4VPSpec.JWKS}' must be provided when encryption is required",
                    ).asException()
                }

                val verifierCandidateEncryptionKeys = verifierAdvertisedJwkSet.keys
                    .filterNot { it.keyID.isNullOrBlank() || it.algorithm?.name.isNullOrBlank() }

                responseEncryptionSpecification(
                    responseEncryptionConfiguration,
                    verifierCandidateEncryptionKeys,
                    verifierSupportedEncryptionMethods
                        ?: setOf(EncryptionMethod.parse(OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED_DEFAULT)),
                )
            }

        val vpFormatsSupported =
            if (null != query) vpFormats(unvalidated, query, walletSupportedVpFormats)
            else unvalidated.vpFormatsSupported

        return ValidatedClientMetaData(responseEncryptionSpecification, vpFormatsSupported)
    }
}

private fun jwks(unvalidated: UnvalidatedClientMetaData): JWKSet? {
    fun JsonObject.asJWKSet(): JWKSet = try {
        JWKSet.parse(jsonSupport.encodeToString(this))
    } catch (ex: ParseException) {
        throw ResolutionError.ClientMetadataJwksUnparsable(ex).asException()
    }

    val jwkSet = unvalidated.jwks?.asJWKSet()
    if (null != jwkSet) {
        ensure(jwkSet.keys.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData("'${OpenId4VPSpec.JWKS}' cannot be empty").asException()
        }

        val keyIds = jwkSet.keys.map { it.keyID }
        ensure(keyIds.size == keyIds.toSet().size) {
            RequestValidationError.InvalidClientMetaData("Each JWK must have a unique `kid`").asException()
        }
    }

    return jwkSet
}

private fun responseEncryptionMethodsSupported(unvalidated: UnvalidatedClientMetaData): Set<EncryptionMethod>? {
    val encryptionMethods = unvalidated.responseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) }
    if (null != encryptionMethods) {
        ensure(encryptionMethods.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData(
                "'${OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED}' must not be empty",
            ).asException()
        }
    }

    return encryptionMethods?.toSet()
}

private fun vpFormats(
    unvalidated: UnvalidatedClientMetaData,
    query: DCQL,
    walletSupportedVpFormats: VpFormatsSupported,
): VpFormatsSupported {
    val queryFormats = query.credentials.value.map { credential -> credential.format }.toSet()
    ensure(unvalidated.vpFormatsSupported.containsAll(queryFormats)) {
        RequestValidationError.InvalidClientMetaData(
            "Verifier does not support all Formats requested in the DCQL query",
        ).asException()
    }
    val verifierQueryVpFormatsSupported = unvalidated.vpFormatsSupported.filter(queryFormats)
    return resolveCommonGround(walletSupportedVpFormats, verifierQueryVpFormatsSupported)
}

/**
 * Method checks whether Wallet can fulfill the Verifier's authorization response encryption requirements.
 *
 * @param walletConfiguration the [encryption parameters][ResponseEncryptionConfiguration] supported by the Wallet
 * @param verifierCandidateEncryptionKeys the JWKS advertised by the Verifier in his Client Metadata
 * @param verifierSupportedEncryptionMethods the EncryptionMethods advertised by the Verifier in his Client Metadata
 *
 * @return [ResponseEncryptionSpecification] the encryption parameters that can be used by the Wallet to fulfill the
 * Verifier's encryption requirements
 * @throws AuthorizationRequestException in case the Wallet does not support any of the encryption parameters that
 * can fulfill the Verifier's  encryption requirements
 */
@Throws(AuthorizationRequestException::class)
private fun responseEncryptionSpecification(
    walletConfiguration: ResponseEncryptionConfiguration,
    verifierCandidateEncryptionKeys: List<JWK>,
    verifierSupportedEncryptionMethods: Set<EncryptionMethod>,
): ResponseEncryptionSpecification {
    ensure(walletConfiguration is ResponseEncryptionConfiguration.Supported) {
        UnsupportedClientMetaData("Wallet doesn't support encrypting authorization responses").asException()
    }

    ensure(verifierSupportedEncryptionMethods.isNotEmpty()) {
        RequestValidationError.InvalidClientMetaData(
            "No encryption methods were advertised by the Verifier in his Client Metadata",
        ).asException()
    }
    val encryptionMethod = walletConfiguration.supportedMethods.firstOrNull {
        it in verifierSupportedEncryptionMethods
    } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption methods supported by Verifier").asException()

    ensure(verifierCandidateEncryptionKeys.isNotEmpty()) {
        RequestValidationError.InvalidClientMetaData(
            "No encryption JWKs were advertised by the Verifier in his Client Metadata",
        ).asException()
    }
    val (encryptionAlgorithm, encryptionKey) = walletConfiguration.supportedAlgorithms.firstNotNullOfOrNull { supportedAlgorithm ->
        val encryptionKey = verifierCandidateEncryptionKeys.firstOrNull { key ->
            supportedAlgorithm.name == key.algorithm?.name && EncrypterFactory.canBeUsed(supportedAlgorithm, key)
        }

        if (null != encryptionKey) {
            supportedAlgorithm to encryptionKey
        } else {
            null
        }
    } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption algorithms supported by verifier").asException()

    return ResponseEncryptionSpecification(encryptionAlgorithm, encryptionMethod, encryptionKey)
}

private fun resolveCommonGround(
    walletSupported: VpFormatsSupported,
    verifierSupported: VpFormatsSupported,
): VpFormatsSupported {
    val sdJwtVc =
        if (null != verifierSupported.sdJwtVc) {
            walletSupported.sdJwtVc?.let {
                resolveCommonGround(walletSupported = it, verifierSupported = verifierSupported.sdJwtVc)
            }
        } else null

    val msoMdoc =
        if (null != verifierSupported.msoMdoc) {
            walletSupported.msoMdoc?.let {
                resolveCommonGround(walletSupported = it, verifierSupported = verifierSupported.msoMdoc)
            }
        } else null

    ensure(null != sdJwtVc || null != msoMdoc) {
        ResolutionError.ClientVpFormatsNotSupportedFromWallet.asException()
    }

    return VpFormatsSupported(sdJwtVc, msoMdoc)
}

private fun resolveCommonGround(
    walletSupported: VpFormatsSupported.SdJwtVc,
    verifierSupported: VpFormatsSupported.SdJwtVc,
): VpFormatsSupported.SdJwtVc {
    fun common(
        walletSupported: List<JWSAlgorithm>?,
        verifierSupported: List<JWSAlgorithm>?,
    ): List<JWSAlgorithm>? =
        when {
            null != walletSupported && null != verifierSupported -> {
                val common = walletSupported.intersect(verifierSupported).toList().takeIf { it.isNotEmpty() }
                ensureNotNull(common) {
                    ResolutionError.ClientVpFormatsNotSupportedFromWallet.asException()
                }
            }

            else -> verifierSupported ?: walletSupported
        }

    val sdJwtAlgorithms = common(walletSupported.sdJwtAlgorithms, verifierSupported.sdJwtAlgorithms)
    val kbJwtAlgorithms = common(walletSupported.kbJwtAlgorithms, verifierSupported.kbJwtAlgorithms)
    return VpFormatsSupported.SdJwtVc(sdJwtAlgorithms = sdJwtAlgorithms, kbJwtAlgorithms = kbJwtAlgorithms)
}

private fun resolveCommonGround(
    walletSupported: VpFormatsSupported.MsoMdoc,
    verifierSupported: VpFormatsSupported.MsoMdoc,
): VpFormatsSupported.MsoMdoc {
    fun common(
        walletSupported: List<CoseAlgorithm>?,
        verifierSupported: List<CoseAlgorithm>?,
    ): List<CoseAlgorithm>? =
        when {
            null != walletSupported && null != verifierSupported -> {
                val common = walletSupported.intersect(verifierSupported).toList().takeIf { it.isNotEmpty() }
                ensureNotNull(common) {
                    ResolutionError.ClientVpFormatsNotSupportedFromWallet.asException()
                }
            }

            else -> verifierSupported ?: walletSupported
        }

    val issuerAuthAlgorithms = common(walletSupported.issuerAuthAlgorithms, verifierSupported.issuerAuthAlgorithms)
    val deviceAuthAlgorithms = common(walletSupported.deviceAuthAlgorithms, verifierSupported.deviceAuthAlgorithms)
    return VpFormatsSupported.MsoMdoc(issuerAuthAlgorithms = issuerAuthAlgorithms, deviceAuthAlgorithms = deviceAuthAlgorithms)
}
