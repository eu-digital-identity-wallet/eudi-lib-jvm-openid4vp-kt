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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.ClientIdPrefix.*
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.toJsonObject
import kotlinx.serialization.json.*

private const val REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
private const val JWKS = "jwks"

// JAR encryption
private const val REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED = "request_object_encryption_alg_values_supported"
private const val REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED = "request_object_encryption_enc_values_supported"

// Response encryption
private const val AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED = "authorization_encryption_alg_values_supported"
private const val AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED = "authorization_encryption_enc_values_supported"

private const val RESPONSE_TYPES_SUPPOERTED = "response_types_supported"
private const val RESPONSE_MODES_SUPPORTED = "response_modes_supported"

internal fun walletMetaData(cfg: OpenId4VPConfig, clientId: String, keys: List<JWK>): JsonObject =
    buildJsonObject {
        //
        // Authorization Request signature and encryption parameters
        // Uses properties defined in JAR and JARM specs
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post
        //

        // Signature
        val permitsSignedRequestObjects =
            VerifierId.parse(clientId).getOrNull()?.prefix?.permitsSignedRequestObjects() ?: false
        if (permitsSignedRequestObjects) {
            putJsonArray(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) {
                cfg.jarConfiguration.supportedAlgorithms.forEach { alg -> add(alg.name) }
            }
        }

        // Encryption
        cfg.jarConfiguration.supportedRequestUriMethods.isPostSupported()?.let { requestUriMethodPost ->
            val jarEncryption = requestUriMethodPost.jarEncryption
            if (jarEncryption is EncryptionRequirement.Required && keys.isNotEmpty()) {
                put(JWKS, JWKSet(keys).toJSONObject(true).toJsonObject())
                putJsonArray(REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED) {
                    jarEncryption.supportedEncryptionAlgorithms.forEach { alg -> add(alg.name) }
                }
                putJsonArray(REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED) {
                    jarEncryption.supportedEncryptionMethods.forEach { method -> add(method.name) }
                }
            }
        }

        // Response Encryption
        val responseEncryptionConfiguration = cfg.responseEncryptionConfiguration
        if (responseEncryptionConfiguration is ResponseEncryptionConfiguration.Supported) {
            putJsonArray(AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED) {
                responseEncryptionConfiguration.supportedAlgorithms.forEach { alg -> add(alg.name) }
            }
            putJsonArray(AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED) {
                responseEncryptionConfiguration.supportedMethods.forEach { method -> add(method.name) }
            }
        }

        //
        // OpenIdVP
        //
        put(OpenId4VPSpec.VP_FORMATS_SUPPORTED, jsonSupport.encodeToJsonElement(cfg.vpConfiguration.vpFormatsSupported))
        putJsonArray(OpenId4VPSpec.CLIENT_ID_PREFIXES_SUPPORTED) {
            cfg.supportedClientIdPrefixes.forEach { supportedClientIdPrefix ->
                add(supportedClientIdPrefix.prefix().metadataValue)
            }
        }
        putJsonArray(RESPONSE_TYPES_SUPPOERTED) {
            add("vp_token")
        }

        // TODO Investigate is this should be hardcoded, or
        //  if we should add an option to cfg
        putJsonArray(RESPONSE_MODES_SUPPORTED) {
            add("direct_post")
            add("direct_post.jwt")
        }
    }

internal val ClientIdPrefix.metadataValue: String
    get() = when (this) {
        PreRegistered -> OpenId4VPSpec.CLIENT_ID_PREFIX_PRE_REGISTERED
        RedirectUri -> OpenId4VPSpec.CLIENT_ID_PREFIX_REDIRECT_URI
        OpenIdFederation -> OpenId4VPSpec.CLIENT_ID_PREFIX_OPENID_FEDERATION
        DecentralizedIdentifier -> OpenId4VPSpec.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER
        VerifierAttestation -> OpenId4VPSpec.CLIENT_ID_PREFIX_VERIFIER_ATTESTATION
        X509SanDns -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS
        X509Hash -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH
    }
