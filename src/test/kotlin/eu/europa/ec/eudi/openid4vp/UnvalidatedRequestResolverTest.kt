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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingExpectedOrigins
import eu.europa.ec.eudi.openid4vp.RequestValidationError.UnexpectedOrigin
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverDCApi
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverHttp
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequestObject
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.MissingFieldException
import kotlinx.serialization.json.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestInstance
import java.net.URLEncoder
import java.time.Clock
import java.util.*
import kotlin.collections.filter
import kotlin.collections.forEach
import kotlin.collections.listOf
import kotlin.collections.setOf
import kotlin.test.*
import kotlin.test.assertNotNull

class UnvalidatedRequestResolverTest {

    private val dcqlQuery = readFileAsText("dcql/basic_example.json")
        .replace("\r\n", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("  ", "")

    private val dcqlQueryURLEncoded = dcqlQuery.let { URLEncoder.encode(it, "UTF-8") }

    private val signingKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate()

    private val jwkSetJO = Json.parseToJsonElement(
        """ { 
                "keys": [ {
                      "kty": "RSA",
                      "e": "AQAB",
                      "use": "sig",
                      "kid": "a0779cde-0615-41b3-89b7-aec75faa159d",
                      "iat": 1701436001,
                      "n": "k4gz8H4Rvuh7ShPHpOwSPN9SWWBUxApgOuBYzDQOa4rXMmUs20egROvtDQYf2C0o-mZEPUXNq8-I79v9j_Uacum2CQWpOPd7Z-kXGZsE7Z9HAqVPqQnMNUU2aQPc8WYbkrXOrFjFIo0GQuVObVMN_1wh2k94JLFoqRAx2TLMrRu-pQUQfN1iTL-2yL3Cn-Ri3W_sxhdLV0uKdviKcU437LdvrpE3eoXePxofmDxG2udX6TSqNvzRZpKR9Vqy9hKaTppAHp_0G1fQ4dSCLpSY9hxGEuTFgFAyvtZZhZrL2OFa6XHPC60uX5-Iir2K0IymSPrVpftxNUACKebkh5FTGw"
                    } ] 
        } 
        """.trimIndent(),
    ).jsonObject

    private val vpFormatsJO = Json.parseToJsonElement(
        """ { 
               "mso_mdoc": {
                 "issuerauth_alg_values": [-7, -9],
                 "deviceauth_alg_values": [-7, -9]
               },
               "dc+sd-jwt": {
                   "sd-jwt_alg_values": ["ES256"],
                   "kb-jwt_alg_values": ["ES256"]
               }
            }                 
        """.trimIndent(),
    ).jsonObject

    val didAlgAndKey = randomKey()

    private val walletConfig = OpenId4VPConfig(
        supportedClientIdPrefixes = listOf(
            SupportedClientIdPrefix.Preregistered(
                PreregisteredClient(
                    clientId = "Verifier",
                    legalName = "Verifier",
                    jarConfig = JWSAlgorithm.RS256 to JWKSet(signingKey).toPublicJWKSet(),
                ),
            ),
            SupportedClientIdPrefix.RedirectUri,
            SupportedClientIdPrefix.X509SanDns(::validateChain),
            SupportedClientIdPrefix.X509Hash(::validateChain),
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
        supportedTransactionDataTypes = listOf(
            SupportedTransactionDataType.SdJwtVc(
                TransactionDataType("basic-transaction-data"),
                setOf(HashAlgorithm.SHA_256, HashAlgorithm("sha-384")),
            ),
        ),
        clock = Clock.systemDefaultZone(),
    )

    private val clientMetadataJwksInline =
        """ {
             "jwks": $jwkSetJO,
             "vp_formats_supported": $vpFormatsJO
            } 
        """.trimIndent().let {
            URLEncoder.encode(it, "UTF-8")
        }

    @DisplayName("when authorization request comes through redirects")
    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    inner class RequestResolutionOverRedirectsTest {

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

        private fun resolver() = DefaultRequestResolverOverHttp(walletConfig, httpClient)

        @Test
        fun `vp token auth request`() = runTest {
            suspend fun test(state: String? = null) {
                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_token" +
                        "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&nonce=n-0S6_WzA2Mj" +
                        (state?.let { "&state=$it" } ?: "") +
                        "&dcql_query=$dcqlQueryURLEncoded" +
                        "&client_metadata=$clientMetadataJwksInline"

                val resolution = resolver().resolveRequestUri(authRequest)
                resolution.assertIsSuccess()
            }

            test(genState())
            test()
        }

        @Test
        fun `if response_mode does not require encryption, related client_metadata are not mandatory to be provided`() = runTest {
            suspend fun test(state: String? = null) {
                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_token" +
                        "&response_mode=direct_post" +
                        "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                        "&response_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&nonce=n-0S6_WzA2Mj" +
                        (state?.let { "&state=$it" } ?: "") +
                        "&dcql_query=$dcqlQueryURLEncoded"

                val resolution = resolver().resolveRequestUri(authRequest)

                resolution.assertIsSuccess()
            }

            test(genState())
            test()
        }

        @Test
        fun `JAR auth request, request passed as JWT, verified with pre-registered client prefix`() = runBlocking {
            suspend fun test(typ: JOSEObjectType? = null, assertions: (Resolution) -> Unit) {
                val jwkSet = JWKSet(signingKey)
                val unvalidatedClientMetaData = UnvalidatedClientMetaData(
                    jwks = Json.parseToJsonElement(jwkSet.toPublicJWKSet().toString()).jsonObject,
                    vpFormatsSupported = VpFormatsSupported(
                        msoMdoc =
                            VpFormatsSupported.MsoMdoc(
                                issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                            ),
                    ),
                )
                val signedJwt = unvalidatedRequestOverRedirects(
                    clientId = "Verifier",
                    dcqlQuery = readFileAsText("dcql/eudi_msomdoc_pid_dcql_query.json"),
                    responseUri = "https://eudi.netcompany-intrasoft.com/wallet/direct_post",
                    clientMetadata = unvalidatedClientMetaData,
                ).signWithJwkSet(jwkSet, typ)

                val authRequest = "http://localhost:8080/public_url?client_id=Verifier&request=$signedJwt"
                val resolution = resolver().resolveRequestUri(authRequest)

                assertions(resolution)
            }

            test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
                it.assertIsSuccess()
            }

            listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
                .forEach { type ->
                    test(type) {
                        it.assertIsInvalid<RequestValidationError.InvalidJarJwt>()
                    }
                }
        }

        @Test
        fun `JAR auth request, request passed as JWT, verified with x509_san_dns prefix`() = runTest {
            suspend fun test(typ: JOSEObjectType? = null, assertions: (Resolution) -> Unit) {
                val clientId = "x509_san_dns:verifier.example.gr"
                val signedJwt = unvalidatedRequestOverRedirects(
                    clientId = clientId,
                    responseUri = "https://verifier.example.gr/wallet/direct_post",
                    dcqlQuery = readFileAsText("dcql/eudi_msomdoc_pid_dcql_query.json"),
                    clientMetadata = UnvalidatedClientMetaData(
                        jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                        vpFormatsSupported = VpFormatsSupported(
                            msoMdoc =
                                VpFormatsSupported.MsoMdoc(
                                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                ),
                        ),
                    ),
                ).signWithKeystore(typ)

                val authRequest = "http://localhost:8080/public_url?client_id=$clientId&request=$signedJwt"

                val resolution = resolver().resolveRequestUri(authRequest)
                assertions(resolution)
            }

            test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
                it.assertIsSuccess()
            }

            listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
                .forEach { type ->
                    test(type) {
                        it.assertIsInvalid<RequestValidationError.InvalidJarJwt>()
                    }
                }
        }

        @Test
        fun `JAR auth request, request passed as JWT, verified with x509_hash prefix`() = runTest {
            suspend fun test(typ: JOSEObjectType? = null, assertions: (Resolution) -> Unit) {
                val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
                val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")
                val signedJwt = unvalidatedRequestOverRedirects(
                    clientId = clientId,
                    responseUri = "https://verifier.example.gr",
                    dcqlQuery = readFileAsText("dcql/eudi_msomdoc_pid_dcql_query.json"),
                    clientMetadata = UnvalidatedClientMetaData(
                        jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                        vpFormatsSupported = VpFormatsSupported(
                            msoMdoc =
                                VpFormatsSupported.MsoMdoc(
                                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                ),
                        ),
                    ),
                ).signWithKeystore(typ)

                val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
                val resolution = resolver().resolveRequestUri(authRequest)

                assertions(resolution)
            }

            test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
                it.assertIsSuccess()
            }

            listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
                .forEach { type ->
                    test(type) {
                        it.assertIsInvalid<RequestValidationError.InvalidJarJwt>()
                    }
                }
        }

        @Test
        fun `invalid client metadata - no vp_formats`() = runTest {
            val clientMetadataNoVpFormats =
                """ {
             "jwks": $jwkSetJO
            } 
                """.trimIndent().let {
                    URLEncoder.encode(it, "UTF-8")
                }

            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&dcql_query=$dcqlQueryURLEncoded" +
                    "&client_metadata=$clientMetadataNoVpFormats"

            assertFailsWith<MissingFieldException> {
                resolver().resolveRequestUri(authRequest)
            }
        }

        @Test
        fun `if no common ground on wallet and verifier vp_formats resolution fails with ClientVpFormatsNotSupportedFromWallet`() =
            runTest {
                val clientMetadata =
                    """ {
                 "jwks": $jwkSetJO,
                 "vp_formats_supported": {
                     "dc+sd-jwt": {
                         "sd-jwt_alg_values": ["ES384"],
                         "kb-jwt_alg_values": ["ES384"]
                     }
                 }    
               }
                    """.trimIndent().let {
                        URLEncoder.encode(it, "UTF-8")
                    }

                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_token" +
                        "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&nonce=n-0S6_WzA2Mj" +
                        "&dcql_query=$dcqlQueryURLEncoded" +
                        "&client_metadata=$clientMetadata"

                val resolution = resolver().resolveRequestUri(authRequest)
                resolution.assertIsInvalid<ResolutionError.ClientVpFormatsNotSupportedFromWallet>()
            }

        @Test
        fun `if no common ground between wallet and verifier on non query requested vp_formats resolution succeeds`() = runTest {
            val clientMetadata =
                """ {
                 "jwks": $jwkSetJO,
                 "vp_formats_supported": {
                     "dc+sd-jwt": {
                         "sd-jwt_alg_values": ["ES512"],
                         "kb-jwt_alg_values": ["ES512"]
                     },
                     "mso_mdoc": {
                         "issuerauth_alg_values": [-49, -264],
                         "deviceauth_alg_values": [-49, -264]
                     }
                 }    
               }
                """.trimIndent().let {
                    URLEncoder.encode(it, "UTF-8")
                }

            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&dcql_query=$dcqlQueryURLEncoded" +
                    "&client_metadata=$clientMetadata"

            val resolution = resolver().resolveRequestUri(authRequest)
            with(resolution.assertIsSuccess()) {
                with(assertNotNull(vpFormatsSupported)) {
                    assertNotNull(sdJwtVc)
                    assertEquals(listOf(JWSAlgorithm.ES512), sdJwtVc.sdJwtAlgorithms)
                    assertEquals(listOf(JWSAlgorithm.ES512), sdJwtVc.kbJwtAlgorithms)
                    assertNull(msoMdoc)
                }
            }
        }

        @Test
        fun `if no client metadata provided no vpFormats are included in the resolved authorization request`() = runTest {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&dcql_query=$dcqlQueryURLEncoded"

            val resolution = resolver().resolveRequestUri(authRequest)
            val request = resolution.assertIsSuccess()

            assertNull(request.vpFormatsSupported)
        }

        @Test
        fun `common ground on dc+sd-jwt vp_format includes only common algorithms`() = runTest {
            val clientMetadata =
                """ {
                 "jwks": $jwkSetJO,
                 "vp_formats_supported": {
                     "dc+sd-jwt": {
                         "sd-jwt_alg_values": ["RS256", "ES512", "ES256", "ES384"],
                         "kb-jwt_alg_values": ["RS256", "ES512", "ES384"]
                     }
                 }    
               }
                """.trimIndent().let {
                    URLEncoder.encode(it, "UTF-8")
                }

            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&dcql_query=$dcqlQueryURLEncoded" +
                    "&client_metadata=$clientMetadata"

            val resolution = resolver().resolveRequestUri(authRequest)
            val request = resolution.assertIsSuccess()
            val formats = request.vpFormatsSupported
            val sdJwtFormat = assertNotNull(formats?.sdJwtVc)

            assertNotNull(sdJwtFormat.kbJwtAlgorithms)
            assertTrue { sdJwtFormat.kbJwtAlgorithms.size == 2 }
            assertTrue { sdJwtFormat.kbJwtAlgorithms.contains(JWSAlgorithm.ES512) }
            assertTrue { sdJwtFormat.kbJwtAlgorithms.contains(JWSAlgorithm.RS256) }

            assertNotNull(sdJwtFormat.sdJwtAlgorithms)
            assertTrue { sdJwtFormat.sdJwtAlgorithms.size == 3 }
            assertTrue { sdJwtFormat.sdJwtAlgorithms.contains(JWSAlgorithm.ES256) }
            assertTrue { sdJwtFormat.sdJwtAlgorithms.contains(JWSAlgorithm.ES512) }
            assertTrue { sdJwtFormat.sdJwtAlgorithms.contains(JWSAlgorithm.RS256) }
        }

        @Test
        fun `common ground on msoMdoc vp_format includes only common algorithms`() = runTest {
            val multipleCredentialsDcqlQuery = readFileAsText("dcql/eudi_msomdoc_pid_dcql_query.json")
                .replace("\r\n", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("  ", "")
                .let { URLEncoder.encode(it, "UTF-8") }

            val clientMetadata =
                """ {
                 "jwks": $jwkSetJO,
                 "vp_formats_supported": {
                     "mso_mdoc": {
                         "issuerauth_alg_values": [-49, -7, -264],
                         "deviceauth_alg_values": [-49, -7, -264]
                     }
                 }    
               }
                """.trimIndent().let {
                    URLEncoder.encode(it, "UTF-8")
                }

            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&dcql_query=$multipleCredentialsDcqlQuery" +
                    "&client_metadata=$clientMetadata"

            val resolution = resolver().resolveRequestUri(authRequest)
            val request = resolution.assertIsSuccess()
            val formats = request.vpFormatsSupported
            assertNull(formats?.sdJwtVc)
            val msoMdocFormat = assertNotNull(formats?.msoMdoc)

            assertNotNull(msoMdocFormat.issuerAuthAlgorithms)
            assertTrue { msoMdocFormat.issuerAuthAlgorithms.size == 1 }
            assertTrue { msoMdocFormat.issuerAuthAlgorithms.contains(CoseAlgorithm(-7)) }

            assertNotNull(msoMdocFormat.deviceAuthAlgorithms)
            assertTrue { msoMdocFormat.issuerAuthAlgorithms.size == 1 }
            assertTrue { msoMdocFormat.issuerAuthAlgorithms.contains(CoseAlgorithm(-7)) }
        }

        @Test
        fun `response type provided is miss-spelled`() = runTest {
            suspend fun test(state: String? = null) {
                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_tokens" +
                        "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&nonce=n-0S6_WzA2Mj" +
                        (state?.let { "&state=$it" } ?: "") +
                        "&client_metadata=$clientMetadataJwksInline"

                val resolution = resolver().resolveRequestUri(authRequest)

                resolution.assertIsInvalid<RequestValidationError.UnsupportedResponseType>()
            }

            test(genState())
            test()
        }

        @Test
        fun `nonce validation`() = runTest {
            suspend fun test(state: String? = null) {
                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_token" +
                        "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                        (state?.let { "&state=$it" } ?: "") +
                        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&client_metadata=$clientMetadataJwksInline"

                val resolution = resolver().resolveRequestUri(authRequest)

                resolution.assertIsInvalid<RequestValidationError.MissingNonce>()
            }

            test(genState())
            test()
        }

        @Test
        fun `if client_id is missing reject the request`() = runTest {
            suspend fun test(state: String? = null) {
                val authRequest =
                    "https://client.example.org/universal-link?" +
                        "response_type=vp_token" +
                        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                        "&nonce=n-0S6_WzA2Mj" +
                        (state?.let { "&state=$it" } ?: "") +
                        "&client_metadata=$clientMetadataJwksInline"

                val resolution = resolver().resolveRequestUri(authRequest)

                resolution.assertIsInvalid<RequestValidationError.MissingClientId>()
            }

            test(genState())
            test()
        }
    }

    @DisplayName("when authorization request comes through DC API channel")
    @Nested
    inner class RequestResolutionOverDCApiTest {

        private val resolver = DefaultRequestResolverOverDCApi(walletConfig)

        private val clientMetadata =
            """ {
                 "jwks": $jwkSetJO,
                 "vp_formats_supported": {
                     "dc+sd-jwt": {
                         "sd-jwt_alg_values": ["RS256", "ES512", "ES256", "ES384"],
                         "kb-jwt_alg_values": ["RS256", "ES512", "ES384"]
                     }
                 }    
               }
            """.trimIndent()

        @Test
        fun `nonce is mandatory to exist`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api")
                put("response_type", "vp_token")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            assertIs<Resolution.Invalid>(resolution)
            assertIs<RequestValidationError.MissingNonce>(resolution.error)
        }

        @Test
        fun `response_mode must be dc_api or dc_api jwt`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "fragment")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            val invalid = resolution.assertIsInvalid<RequestValidationError.UnsupportedResponseMode>()
            assertEquals("fragment", invalid.value)
        }

        @Test
        fun `and no presentation query passed, resolution fails`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            resolution.assertIsInvalid<RequestValidationError.MissingQuerySource>()
        }

        @Test
        fun `if response_mode is dc_api jwt, client metadata must be included in request`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api.jwt")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            val invalid = resolution.assertIsInvalid<RequestValidationError.InvalidClientMetaData>()
            assertEquals("Missing client metadata", invalid.cause)
        }

        @Test
        fun `if exchange protocol is not supported, resolution fails`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api.jwt")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
            }
            var resolution = resolver.resolveRequestObject("org-iso-mdoc", "test_origin", requestData)
            resolution.assertIsInvalid<ResolutionError.UnsupportedDcApiExchangeProtocol>()

            resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED, "test_origin", requestData,
            )
            resolution.assertIsInvalid<ResolutionError.DcApiExchangeProtocolNotMatchesReceivedRequest>()
        }

        @Test
        fun `client_id is ignored if provided in unsigned request`() = runTest {
            val requestData = buildJsonObject {
                put("client_id", "client_id")
                put("response_mode", "dc_api")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            val request = resolution.assertIsSuccess()
            assertIs<Client.Origin>(request.client)
            assertEquals("test_origin", request.client.clientId)
        }

        @Test
        fun `client_id is not mandatory to exist in unsigned request over DC API`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            val request = resolution.assertIsSuccess()
            assertIs<Client.Origin>(request.client)
            assertEquals("test_origin", request.client.clientId)
        }

        @Test
        fun `verifier attestations are parsed correctly`() = runTest {
            val requestData = buildJsonObject {
                put("response_mode", "dc_api")
                put("response_type", "vp_token")
                put("nonce", "n-0S6_WzA2Mj")
                put("dcql_query", jsonSupport.decodeFromString<JsonObject>(dcqlQuery))
                put("client_metadata", jsonSupport.decodeFromString<JsonObject>(clientMetadata))
                putJsonArray("verifier_info", {
                    add(
                        buildJsonObject {
                            put("format", "jwt")
                            put("data", "attestation_data")
                        },
                    )
                    add(
                        buildJsonObject {
                            put("format", "jwt")
                            put("data", "attestation_data_1")
                        },
                    )
                })
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED,
                "test_origin",
                requestData,
            )
            val request = resolution.assertIsSuccess()

            assertNotNull(request.verifierInfo)

            val jwtAttestations = request.verifierInfo.attestations.filter {
                it.format == VerifierInfo.Attestation.Format.Jwt
            }.size
            assertEquals(2, jwtAttestations)
        }

        @Test
        fun `when request is of JWS compact serialization form, it is parsed properly`() = runTest {
            val clientId = "x509_san_dns:verifier.example.gr"
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                responseMode = "dc_api",
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf("test_origin"),
            ).signWithKeystore()

            val requestData = buildJsonObject {
                put("request", signedJwt)
            }
            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                "test_origin",
                requestData,
            )
            val request = resolution.assertIsSuccess()
            assertIs<Client.X509SanDns>(request.client)
        }

        @Test
        fun `if request is signed and expected_origins is missing, fail resolution with MissingExpectedOrigins`() = runTest {
            val clientId = "x509_san_dns:verifier.example.gr"
            // Request with no expected_origins
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                responseMode = "dc_api",
                dcqlQuery = dcqlQuery,
            ).signWithKeystore()

            val requestData = buildJsonObject {
                put("request", signedJwt)
            }

            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                "test_origin",
                requestData,
            )
            resolution.assertIsInvalid<MissingExpectedOrigins>()
        }

        @Test
        fun `if request is signed, caller info's origin must be one of the expected_origins`() = runTest {
            val clientId = "x509_san_dns:verifier.example.gr"
            // Request with no expected_origins
            val signedJwt = unvalidatedRequestOverDCApi(
                clientId = clientId,
                responseMode = "dc_api",
                dcqlQuery = dcqlQuery,
                expectedOrigins = listOf("origin_1", "origin_2"),
            ).signWithKeystore()

            val requestData = buildJsonObject {
                put("request", signedJwt)
            }

            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED,
                "test_origin",
                requestData,
            )
            resolution.assertIsInvalid<UnexpectedOrigin>()
        }

        @Test
        fun `if request is multi-signed, client in resolved request object must match wallet's configuration`() = runTest {
            val request = UnvalidatedRequestObject(
                responseMode = "dc_api",
                responseType = "vp_token",
                nonce = "nonce",
                dcqlQuery = jsonSupport.decodeFromString<JsonObject>(dcqlQuery),
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(
                    didSigner(didAlgAndKey),
                ),
            )
            val requestData = buildJsonObject {
                put("request", Json.encodeToJsonElement(request.jwsJson))
            }

            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED,
                "test_origin",
                requestData.jsonObject,
            )

            val resolvedRequestObject = resolution.assertIsSuccess()
            assertIs<Client.DecentralizedIdentifier>(resolvedRequestObject.client)
        }

        @Test
        fun `if request is multi-signed, if no matching client authentication present, resolution fails`() = runTest {
            val request = UnvalidatedRequestObject(
                responseMode = "dc_api",
                responseType = "vp_token",
                nonce = "nonce",
                dcqlQuery = jsonSupport.decodeFromString<JsonObject>(dcqlQuery),
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(
                    verifierAttestationSigner(didAlgAndKey, Clock.systemDefaultZone()),
                ),
            )
            val requestData = buildJsonObject {
                put("request", Json.encodeToJsonElement(request.jwsJson))
            }

            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED,
                "test_origin",
                requestData.jsonObject,
            )

            resolution.assertIsInvalid<RequestValidationError.NoMatchingClientPrefixInMultiSignedRequest>()
        }

        @Test
        fun `if request is multi-signed, if no matching expected origin present, resolution fails`() = runTest {
            val request = UnvalidatedRequestObject(
                responseMode = "dc_api",
                responseType = "vp_token",
                nonce = "nonce",
                dcqlQuery = jsonSupport.decodeFromString<JsonObject>(dcqlQuery),
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(
                    didSigner(didAlgAndKey),
                ),
            )
            val requestData = buildJsonObject {
                put("request", Json.encodeToJsonElement(request.jwsJson))
            }

            val resolution = resolver.resolveRequestObject(
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED,
                "other_origin",
                requestData.jsonObject,
            )

            resolution.assertIsInvalid<UnexpectedOrigin>()
        }
    }
}
