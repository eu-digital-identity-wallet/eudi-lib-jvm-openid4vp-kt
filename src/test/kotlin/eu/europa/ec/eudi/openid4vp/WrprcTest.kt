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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vp.RegistrationCertificatePolicy.PolicyViolation
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.VerifierInfoTO
import eu.europa.ec.eudi.openid4vp.internal.request.randomKey
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.*
import java.io.InputStream
import java.net.URLEncoder
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class WrprcTest {

    val wrprcValid = load("certificates/wrprc.txt").bufferedReader().readText()

    val didAlgAndKey = randomKey()

    val dcqlQuery = load("dcql/basic_example.json").bufferedReader().readText()
        .replace("\r\n", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("  ", "")

    private val unvalidatedClientMetaData = UnvalidatedClientMetaData(
        vpFormatsSupported = VpFormatsSupported(
            msoMdoc =
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            sdJwtVc = VpFormatsSupported.SdJwtVc(
                sdJwtAlgorithms = listOf(JWSAlgorithm.ES512, JWSAlgorithm.ES256, JWSAlgorithm.RS256),
                kbJwtAlgorithms = listOf(JWSAlgorithm.ES512, JWSAlgorithm.ES256, JWSAlgorithm.RS256),
            ),
        ),
    )

    private val walletConfig = OpenId4VPConfig(
        supportedClientIdPrefixes = listOf(
            SupportedClientIdPrefix.X509Hash({ _ -> true }),
            SupportedClientIdPrefix.DecentralizedIdentifier({ _ -> didAlgAndKey.second.toECPublicKey() }),
        ),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.RS256),
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.Expect(ClientIdPrefix.DecentralizedIdentifier),
        ),
        vpFormatsSupported = VpFormatsSupported(
            VpFormatsSupported.SdJwtVc(
                sdJwtAlgorithms = listOf(
                    JWSAlgorithm.ES512,
                    JWSAlgorithm.ES256,
                    JWSAlgorithm.RS256,
                ),
                kbJwtAlgorithms = listOf(
                    JWSAlgorithm.ES512,
                    JWSAlgorithm.ES256,
                    JWSAlgorithm.RS256,
                ),
            ),
            VpFormatsSupported.MsoMdoc(
                issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
            ),
        ),
        clock = Clock.systemDefaultZone(),
    )

    @DisplayName("when authorization request comes over redirects channel")
    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    inner class WrpRcVerificationRedirectsTest {

        private val json: Json by lazy { Json { ignoreUnknownKeys = true } }
        private lateinit var httpClient: HttpClient

        @BeforeAll
        fun setup() {
            httpClient = HttpClient {
                install(ContentNegotiation) {
                    json(json)
                }
                expectSuccess = true
            }
        }

        @AfterAll
        fun teardown() {
            httpClient.close()
        }

        private fun openId4Vp(walletConfig: OpenId4VPConfig): OpenId4Vp.OverRedirects =
            OpenId4Vp.overRedirects(walletConfig, httpClient)

        @Test
        fun `and registration policy is not set, requests without WRPRC can be resolved`() = runTest {
            val openId4Vp = openId4Vp(walletConfig)

            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")

            val signedJwt = unvalidatedRequestOverRedirects(
                clientId = clientId,
                clientMetadata = unvalidatedClientMetaData,
                dcqlQuery = dcqlQuery,
                verifierInfo = null,
            ).signWithKeystore()

            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
            val resolution = openId4Vp.resolveRequestUri(authRequest)

            assertIs<Resolution.Success>(resolution)
            assert(resolution.policyViolationWarnings.isEmpty())
        }

        @Test
        fun `and registration policy is set, requests without WRPRC cannot be resolved`() = runTest {
            val openId4Vp = openId4Vp(
                walletConfig.withWrprcPolicy(
                    RegistrationCertificatePolicy(
                        trust = { _ -> true },
                        apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() },
                    ),
                ),
            )

            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")

            val signedJwt = unvalidatedRequestOverRedirects(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = null,
            ).signWithKeystore()

            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
            val resolution = openId4Vp.resolveRequestUri(authRequest)

            assertIs<Resolution.Invalid>(resolution)
            assertIs<AuthorizationPolicyValidationError.MissingRequiredRegistrationCertificate>(resolution.error)
        }

        @Test
        fun `and wrprc policy evaluation has violation warnings, resolution succeeds and warnings are reflected in Resolution`() = runTest {
            val policyViolationWarnings = listOf(
                PolicyViolation("violation 1"),
                PolicyViolation("violation warning 2"),
                PolicyViolation("violation warning 3"),
            )
            val openId4Vp = openId4Vp(
                walletConfig
                    .withWrprcPolicy(
                        RegistrationCertificatePolicy(
                            trust = { _ -> true },
                            apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted(policyViolationWarnings) },
                        ),
                    ),
            )

            val verifierInfo = VerifierInfo(
                listOf(
                    VerifierInfo.Attestation(
                        VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                        VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                    ),
                ),
            )

            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")

            val signedJwt = unvalidatedRequestOverRedirects(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = verifierInfo,
            ).signWithKeystore()

            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
            val resolution = openId4Vp.resolveRequestUri(authRequest)

            assertIs<Resolution.Success>(resolution)
            assertNotNull(resolution.policyViolationWarnings)
            assertEquals(policyViolationWarnings, resolution.policyViolationWarnings)
        }

        @Test
        fun `and wrprc policy evaluation fails, resolution fails with AuthorizationPolicyNotMet`() = runTest {
            val policyViolationError = PolicyViolation("Policy violated")
            val openId4Vp = openId4Vp(
                walletConfig
                    .withWrprcPolicy(
                        RegistrationCertificatePolicy(
                            trust = { _ -> true },
                            apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.NotGranted(policyViolationError) },
                        ),
                    ),
            )
            val verifierInfo = VerifierInfo(
                listOf(
                    VerifierInfo.Attestation(
                        VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                        VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                    ),
                ),
            )
            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")

            val signedJwt = unvalidatedRequestOverRedirects(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = verifierInfo,
            ).signWithKeystore()

            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
            val resolution = openId4Vp.resolveRequestUri(authRequest)

            assertIs<Resolution.Invalid>(resolution)
            assertIs<AuthorizationPolicyValidationError.AuthorizationPolicyNotMet>(resolution.error)
        }
    }

    @DisplayName("when authorization request comes through DC API channel")
    @Nested
    inner class WrpRcVerificationDCApiTest {

        private val ORIGIN = "https://verifier.example.gr"

        private fun openId4Vp(walletConfig: OpenId4VPConfig): OpenId4Vp.OverDcAPI =
            OpenId4Vp.overDcApi(walletConfig)

        @Test
        fun `and registration policy is not set, requests without WRPRC can be resolved`() = runTest {
            val openId4Vp = openId4Vp(walletConfig)

            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf(ORIGIN),
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = null,
            ).signWithKeystore()

            val resolution = openId4Vp.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                ORIGIN,
                buildJsonObject {
                    put("request", signedJwt)
                },
            )

            assertIs<Resolution.Success>(resolution)
            assert(resolution.policyViolationWarnings.isEmpty())
        }

        @Test
        fun `and registration policy is set, requests without WRPRC cannot be resolved`() = runTest {
            val openId4Vp = openId4Vp(
                walletConfig.withWrprcPolicy(
                    RegistrationCertificatePolicy(
                        trust = { _ -> true },
                        apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() },
                    ),
                ),
            )

            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf(ORIGIN),
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = null,
            ).signWithKeystore()

            val resolution = openId4Vp.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                ORIGIN,
                buildJsonObject {
                    put("request", signedJwt)
                },
            )
            assertIs<Resolution.Invalid>(resolution)
            assertIs<AuthorizationPolicyValidationError.MissingRequiredRegistrationCertificate>(resolution.error)
        }

        @Test
        fun `and wrprc policy evaluation has violation warnings, resolution succeeds and warnings are reflected in Resolution`() = runTest {
            val policyViolationWarnings = listOf(
                PolicyViolation("violation warning 1"),
                PolicyViolation("violation warning 2"),
                PolicyViolation("violation warning 3"),
            )
            val openId4Vp = openId4Vp(
                walletConfig
                    .withWrprcPolicy(
                        RegistrationCertificatePolicy(
                            trust = { _ -> true },
                            apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted(policyViolationWarnings) },
                        ),
                    ),
            )
            val verifierInfo = VerifierInfo(
                listOf(
                    VerifierInfo.Attestation(
                        VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                        VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                    ),
                ),
            )
            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf(ORIGIN),
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = verifierInfo,
            ).signWithKeystore()

            val resolution = openId4Vp.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                ORIGIN,
                buildJsonObject {
                    put("request", signedJwt)
                },
            )
            assertIs<Resolution.Success>(resolution)
            assertNotNull(resolution.policyViolationWarnings)
            assertEquals(policyViolationWarnings, resolution.policyViolationWarnings)
        }

        @Test
        fun `and wrprc policy evaluation fails, resolution fails with AuthorizationPolicyNotMet`() = runTest {
            val policyViolationError = PolicyViolation("Policy violated")
            val openId4Vp = openId4Vp(
                walletConfig
                    .withWrprcPolicy(
                        RegistrationCertificatePolicy(
                            trust = { _ -> true },
                            apply = { _, _, _ -> RegistrationCertificatePolicy.Authorization.NotGranted(policyViolationError) },
                        ),
                    ),
            )
            val verifierInfo = VerifierInfo(
                listOf(
                    VerifierInfo.Attestation(
                        VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                        VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                    ),
                ),
            )
            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf(ORIGIN),
                clientMetadata = unvalidatedClientMetaData,
                verifierInfo = verifierInfo,
            ).signWithKeystore()

            val resolution = openId4Vp.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                ORIGIN,
                buildJsonObject {
                    put("request", signedJwt)
                },
            )

            assertIs<Resolution.Invalid>(resolution)
            assertIs<AuthorizationPolicyValidationError.AuthorizationPolicyNotMet>(resolution.error)
        }
    }
}

internal fun VerifierInfo?.toVerifierInfoTO(): VerifierInfoTO? = this?.let { verifierInfo ->
    val value = Json.encodeToString(verifierInfo.attestations)
    return VerifierInfoTO(Json.decodeFromString(value))
}

internal fun load(f: String): InputStream =
    WrprcTest::class.java.classLoader.getResourceAsStream(f) ?: error("File $f not found")

private fun OpenId4VPConfig.withWrprcPolicy(policy: RegistrationCertificatePolicy): OpenId4VPConfig =
    copy(registrationCertificatePolicy = policy)
