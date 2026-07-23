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
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverHttp
import eu.europa.ec.eudi.openid4vp.internal.request.TransactionDataTO
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.TestInstance
import java.net.URLEncoder
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

@DisplayName("when using transaction_data")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TransactionDataTest {

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

    private val queryWithSingleCredential = readFileAsText("dcql/basic_example.json")
    private val queryWithMultipleCredentials = readFileAsText("dcql/complex_example.json")

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

    private val walletConfig = OpenId4VPConfig(
        supportedClientIdPrefixes = listOf(
            SupportedClientIdPrefix.X509Hash({ _ -> true }),
        ),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.RS256),
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.Expect(ClientIdPrefix.X509Hash),
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

    private suspend fun testAndThen(
        transactionData: JsonArray,
        query: String,
        block: suspend (Resolution) -> Unit,
    ) {
        val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
        val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")

        val clientMetadataJO = buildJsonObject {
            put("jwks", jwkSetJO)
            put("vp_formats_supported", vpFormatsJO)
        }

        val signedJwt = unvalidatedRequestOverRedirects(
            clientId = clientId,
            dcqlQuery = query,
            clientMetadata = json.decodeFromJsonElement<UnvalidatedClientMetaData>(clientMetadataJO),
        )
            .copy(transactionData = TransactionDataTO(transactionData))
            .signWithKeystore()

        val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"
        val resolution = resolver().resolveRequestUri(authRequest)
        block(resolution)
    }

    private suspend fun testAndThen(
        transactionData: JsonObject,
        query: String,
        assertions: suspend (Resolution) -> Unit,
    ) {
        testAndThen(
            JsonArray(
                listOf(
                    JsonPrimitive(base64UrlNoPadding.encode(jsonSupport.encodeToString(transactionData).encodeToByteArray())),
                ),
            ),
            query,
            assertions,
        )
    }

    @Test
    fun `if transaction_data contains non base64url encoded values, resolution fails`() = runTest {
        val transactionData = JsonArray(listOf(JsonPrimitive("invalid")))
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals("The pad bits must be zeros", cause.message)
        }
    }

    @Test
    fun `if transaction_data contains non JsonObject values, resolution fails`() = runTest {
        val transactionData = JsonArray(listOf(JsonPrimitive(base64UrlNoPadding.encode("foo".encodeToByteArray()))))
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<SerializationException>(error.cause)
            assertEquals(
                "Unexpected JSON token at offset 0: Expected start of the object '{', but had 'f' instead at path: $\nJSON input: foo",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains no type, resolution fails`() = runTest {
        val transactionData = JsonObject(emptyMap())
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Missing required property 'type'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains non-string type, resolution fails`() = runTest {
        val transactionData = buildJsonObject {
            put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, 10)
        }
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Property 'type' is not a string'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains unsupported type, resolution fails`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("unsupported"),
            listOf(QueryId("my_credential")),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Unsupported Transaction Data 'type': 'unsupported'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains no credential_ids, resolution fails`() = runTest {
        val transactionData = buildJsonObject {
            put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "basic-transaction-data")
        }
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Missing required property 'credential_ids'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains non-string credential_ids, resolution fails`() = runTest {
        val transactionData = buildJsonObject {
            put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "basic-transaction-data")
            putJsonArray("credential_ids") {
                add(10)
            }
        }
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Property 'credential_ids' is not an array or contains non string values",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains credential_ids that don't match inputdescriptor ids, resolution fails`() =
        runTest {
            val transactionData = TransactionData.sdJwtVc(
                TransactionDataType("basic-transaction-data"),
                listOf(QueryId("invalid-id")),
            )
            testAndThen(transactionData.json, queryWithSingleCredential) {
                val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Invalid Transaction Data 'credential_ids': '[invalid-id]'",
                    cause.message,
                )
            }
        }

    @Test
    fun `if transaction_data contains credential_ids that don't match query ids, resolution fails`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("invalid-id")),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Invalid Transaction Data 'credential_ids': '[invalid-id]'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains credential_ids that have different format, resolution fails`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("my_credential_1"), QueryId("my_credential_2")),
        )
        testAndThen(transactionData.json, queryWithMultipleCredentials) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Transaction Data must refer to Credentials that use the same Format",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains non-list transaction_data_hashes_alg, resolution fails`() = runTest {
        val transactionData = buildJsonObject {
            put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "basic-transaction-data")
            putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                add("my_credential")
            }
            put(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS, "invalid")
        }
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Property 'transaction_data_hashes_alg' is not an array or contains non string values",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains non-string transaction_data_hashes_alg, resolution fails`() = runTest {
        val transactionData = buildJsonObject {
            put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, "basic-transaction-data")
            putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                add("my_credential")
            }
            putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS) {
                add(15)
            }
        }
        testAndThen(transactionData, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Property 'transaction_data_hashes_alg' is not an array or contains non string values",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data contains unsupported transaction_data_hashes_alg, resolution fails`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("my_credential")),
            listOf(HashAlgorithm("sha-512")),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Unsupported Transaction Data 'transaction_data_hashes_alg': '[sha-512]'",
                cause.message,
            )
        }
    }

    @Test
    fun `if transaction_data is valid, when using dcql, resolution succeeds`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("my_credential")),
            listOf(HashAlgorithm.SHA_256),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val request = it.assertIsSuccess()
            val resolvedTransactionData = run {
                val resolvedTransactionData = assertNotNull(request.transactionData)
                assertEquals(1, resolvedTransactionData.size)
                assertIs<TransactionData.SdJwtVc>(resolvedTransactionData.first())
            }
            assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
            assertEquals(
                listOf(QueryId("my_credential")),
                resolvedTransactionData.credentialIds,
            )
            assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithms)
        }
    }

    @Test
    fun `if transaction_data is valid, resolution succeeds`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("my_credential")),
            listOf(HashAlgorithm.SHA_256),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val request = it.assertIsSuccess()
            val resolvedTransactionData = run {
                val resolvedTransactionData = assertNotNull(request.transactionData)
                assertEquals(1, resolvedTransactionData.size)
                assertIs<TransactionData.SdJwtVc>(resolvedTransactionData.first())
            }
            assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
            assertEquals(
                listOf(QueryId("my_credential")),
                resolvedTransactionData.credentialIds,
            )
            assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithms)
        }
    }

    @Test
    fun `if transaction_data is valid, and contains no transaction_data_hashes_alg, resolution succeeds`() =
        runTest {
            val transactionData = TransactionData.sdJwtVc(
                TransactionDataType("basic-transaction-data"),
                listOf(QueryId("my_credential")),
            )
            testAndThen(transactionData.json, queryWithSingleCredential) {
                val request = it.assertIsSuccess()
                val resolvedTransactionData = run {
                    val resolvedTransactionData = assertNotNull(request.transactionData)
                    assertEquals(1, resolvedTransactionData.size)
                    assertIs<TransactionData.SdJwtVc>(resolvedTransactionData.first())
                }
                assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
                assertEquals(
                    listOf(QueryId("my_credential")),
                    resolvedTransactionData.credentialIds,
                )
                assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithmsOrDefault)
            }
        }

    @Test
    fun `if transaction_data is valid, and contains transaction_data_hashes_alg without sha-256, resolution succeeds`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId(("my_credential"))),
            listOf(HashAlgorithm("sha-384")),
        )
        testAndThen(transactionData.json, queryWithSingleCredential) {
            val request = it.assertIsSuccess()
            val resolvedTransactionData = run {
                val resolvedTransactionData = assertNotNull(request.transactionData)
                assertEquals(1, resolvedTransactionData.size)
                assertIs<TransactionData.SdJwtVc>(resolvedTransactionData.first())
            }
            assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
            assertEquals(
                listOf(QueryId("my_credential")),
                resolvedTransactionData.credentialIds,
            )
            assertEquals(listOf(HashAlgorithm("sha-384")), resolvedTransactionData.hashAlgorithms)
        }
    }

    @Test
    fun `if transaction_data format is not supported, resolution fails`() = runTest {
        val transactionData = TransactionData.sdJwtVc(
            TransactionDataType("basic-transaction-data"),
            listOf(QueryId("my_credential_2")),
        )
        testAndThen(transactionData.json, queryWithMultipleCredentials) {
            val error = it.assertIsInvalid<ResolutionError.InvalidTransactionData>()
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals(
                "Unsupported Transaction Data Format 'mso_mdoc'",
                cause.message,
            )
        }
    }
}
