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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlin.test.*

class WalletMetaDataTest {

    @Test
    fun `test with jar encryption`() = runTest {
        val config = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = JarConfiguration.Default.supportedAlgorithms,
                supportedRequestUriMethods = SupportedRequestUriMethods.Post(
                    jarEncryption = EncryptionRequirement.Required(
                        supportedEncryptionAlgorithms = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_ALGORITHMS,
                        supportedEncryptionMethods = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_METHODS,
                        ephemeralEncryptionKeyCurve = Curve.P_521,
                    ),
                ),
            ),
        )
        assertMetadata(config, "x509_san_dns:verifier.example.com")
    }

    @Test
    fun `test without jar encryption`() = runTest {
        val config = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = JarConfiguration.Default.supportedAlgorithms,
                supportedRequestUriMethods = SupportedRequestUriMethods.Get,
            ),
        )
        assertMetadata(config, "x509_san_dns:verifier.example.com")
    }

    @Test
    fun `when clientId permits signed Request Objects, request_object_signing_alg_values_supported MUST be included`() = runTest {
        val config = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                ),
            ),
        )
        val walletMetaData = walletMetaData(config, "x509_san_dns:verifier.example.com", emptyList())
        assertNotNull(walletMetaData["request_object_signing_alg_values_supported"])
    }

    @Test
    fun `when clientId does not permit signed Request Objects, request_object_signing_alg_values_supported MUST NOT be included`() =
        runTest {
            val config = OpenId4VPConfig(
                supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.RedirectUri, SupportedClientIdPrefix.X509SanDns.NoValidation),
                vpConfiguration = VPConfiguration(
                    vpFormatsSupported = VpFormatsSupported(
                        VpFormatsSupported.SdJwtVc.HAIP,
                    ),
                ),
            )
            val walletMetaData = walletMetaData(config, "redirect_uri:https://verifier.example.com/callback", emptyList())
            assertNull(walletMetaData["request_object_signing_alg_values_supported"])
        }
}

private suspend fun assertMetadata(config: OpenId4VPConfig, clientId: String) {
    val (encryptionRequirement, ephemeralJarEncryptionJwks) =
        config.jarConfiguration.supportedRequestUriMethods.isPostSupported()
            ?.let { requestUriMethodPost ->
                when (val jarEncryption = requestUriMethodPost.jarEncryption) {
                    EncryptionRequirement.NotRequired -> jarEncryption to null
                    is EncryptionRequirement.Required -> jarEncryption to jarEncryption.ephemeralEncryptionKey()
                }
            } ?: (EncryptionRequirement.NotRequired to null)

    val walletMetaData = walletMetaData(config, clientId, listOfNotNull(ephemeralJarEncryptionJwks))
        .also {
            println(jsonSupport.encodeToString(it))
        }

    assertExpectedVpFormats(config.vpConfiguration.vpFormatsSupported, walletMetaData)
    assertClientIdPrefix(config.supportedClientIdPrefixes, walletMetaData)
    assertPresentationDefinitionUriSupported(walletMetaData)
    assertJarSigning(config, clientId, walletMetaData)
    assertJarEncryption(encryptionRequirement, ephemeralJarEncryptionJwks, walletMetaData)
    assertResponseTypes(walletMetaData)
}

private fun assertJarSigning(config: OpenId4VPConfig, clientId: String, walletMetaData: JsonObject) {
    val supportedAlgorithms = config.jarConfiguration.supportedAlgorithms
    val permitsSignedRequestObjects = VerifierId.parse(clientId).getOrNull()?.prefix?.permitsSignedRequestObjects() ?: false
    val algs = walletMetaData["request_object_signing_alg_values_supported"]
    if (permitsSignedRequestObjects) {
        assertIs<JsonArray>(algs)
        assertContentEquals(
            supportedAlgorithms.map { it.name },
            algs.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(algs)
    }
}

private fun assertJarEncryption(
    encryptionRequirement: EncryptionRequirement,
    ephemeralJarEncryptionJwk: JWK?,
    walletMetadata: JsonObject,
) {
    when (encryptionRequirement) {
        EncryptionRequirement.NotRequired -> {
            assertNull(ephemeralJarEncryptionJwk)
            assertNull(walletMetadata["jwks"])
            assertNull(walletMetadata["authorization_encryption_alg_values_supported"])
            assertNull(walletMetadata["authorization_encryption_enc_values_supported"])
        }

        is EncryptionRequirement.Required -> {
            assertNotNull(ephemeralJarEncryptionJwk)

            val jwks = assertIs<JsonObject>(walletMetadata["jwks"]).let { JWKSet.parse(jsonSupport.encodeToString(it)) }
            assertEquals(JWKSet(ephemeralJarEncryptionJwk).toPublicJWKSet(), jwks)

            val encryptionAlgorithms = assertIs<JsonArray>(walletMetadata["request_object_encryption_alg_values_supported"]).map {
                JWEAlgorithm.parse(it.jsonPrimitive.content)
            }
            assertEquals(encryptionRequirement.supportedEncryptionAlgorithms, encryptionAlgorithms)

            val encryptionMethods = assertIs<JsonArray>(walletMetadata["request_object_encryption_enc_values_supported"]).map {
                EncryptionMethod.parse(it.jsonPrimitive.content)
            }
            assertEquals(encryptionRequirement.supportedEncryptionMethods, encryptionMethods)
        }
    }
}

private fun assertPresentationDefinitionUriSupported(walletMetaData: JsonObject) {
    val value = walletMetaData["presentation_definition_uri_supported"]
    assertTrue {
        value == null || (value is JsonPrimitive && !value.boolean)
    }
}

private fun assertClientIdPrefix(
    supportedClientIdPrefixes: List<SupportedClientIdPrefix>,
    walletMetaData: JsonObject,
) {
    val prefixes = walletMetaData[OpenId4VPSpec.CLIENT_ID_PREFIXES_SUPPORTED]
    if (supportedClientIdPrefixes.isNotEmpty()) {
        assertIs<JsonArray>(prefixes)
        assertContentEquals(
            supportedClientIdPrefixes.map { it.prefix().metadataValue },
            prefixes.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(prefixes)
    }
}

private fun assertExpectedVpFormats(
    expectedVpFormatsSupported: VpFormatsSupported,
    walletMetaData: JsonObject,
) {
    val vpFormats = assertIs<JsonObject>(
        walletMetaData[OpenId4VPSpec.VP_FORMATS_SUPPORTED],
        "Missing ${OpenId4VPSpec.VP_FORMATS_SUPPORTED}",
    )
    if (expectedVpFormatsSupported.msoMdoc != null) {
        val msoMdoc = assertNotNull(vpFormats["mso_mdoc"])
        assertIs<JsonObject>(msoMdoc)
        assertTrue { msoMdoc.isNotEmpty() }
    }
    val sdJwtVcSupport = expectedVpFormatsSupported.sdJwtVc
    if (sdJwtVcSupport != null) {
        val sdJwtVc = assertNotNull(vpFormats["dc+sd-jwt"])
        assertIs<JsonObject>(sdJwtVc)
        val sdJwtAlgs = sdJwtVc["sd-jwt_alg_values"]
        if (!sdJwtVcSupport.sdJwtAlgorithms.isNullOrEmpty()) {
            assertNotNull(sdJwtAlgs)
            assertIs<JsonArray>(sdJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.sdJwtAlgorithms.map { it.name },
                sdJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(sdJwtAlgs)
        }

        val kbJwtAlgs = sdJwtVc["kb-jwt_alg_values"]
        if (!sdJwtVcSupport.kbJwtAlgorithms.isNullOrEmpty()) {
            assertNotNull(kbJwtAlgs)
            assertIs<JsonArray>(kbJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.kbJwtAlgorithms.map { it.name },
                kbJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(kbJwtAlgs)
        }
    }
}

private fun assertResponseTypes(walletMetadata: JsonObject) {
    val types = assertIs<JsonArray>(walletMetadata["response_types_supported"], "'response_types_supported' is not a json array")
    assert(types.all { it is JsonPrimitive && it.isString }) { "'response_types_supported' does not contain strings only" }

    val values = types.map { it.jsonPrimitive.content }
    assertEquals(1, values.size, "'unexpected number of 'response_types_supported'")
    assert("vp_token" in values) { "'response_types_supported' misses 'vp_token'" }
}
