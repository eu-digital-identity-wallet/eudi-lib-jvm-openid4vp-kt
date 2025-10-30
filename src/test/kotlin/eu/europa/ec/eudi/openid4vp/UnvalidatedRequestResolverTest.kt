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
package eu.europa.ec.eudi.openid4vp

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.MissingFieldException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import org.apache.http.NameValuePair
import org.apache.http.client.utils.URIBuilder
import org.apache.http.message.BasicNameValuePair
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.TestInstance
import java.io.InputStream
import java.net.URLEncoder
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.collections.List
import kotlin.collections.emptyMap
import kotlin.collections.first
import kotlin.collections.forEach
import kotlin.collections.indices
import kotlin.collections.listOf
import kotlin.collections.map
import kotlin.collections.setOf
import kotlin.collections.toMutableList
import kotlin.test.*
import kotlin.test.assertNotNull

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UnvalidatedRequestResolverTest {

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

    private fun resolver() = DefaultAuthorizationRequestResolver(walletConfig, httpClient)

    private val dcqlQuery = readFileAsText("dcql/basic_example.json")
        .replace("\r\n", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("  ", "")
        .let { URLEncoder.encode(it, "UTF-8") }

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

    private val walletConfig = OpenId4VPConfig(
        supportedClientIdPrefixes = listOf(
            SupportedClientIdPrefix.Preregistered(
                PreregisteredClient(
                    clientId = "Verifier",
                    legalName = "Verifier",
                    jarConfig = JWSAlgorithm.RS256 to JwkSetSource.ByValue(
                        Json.parseToJsonElement(
                            JWKSet(signingKey).toPublicJWKSet().toString(),
                        ).jsonObject,
                    ),
                ),
            ),
            SupportedClientIdPrefix.RedirectUri,
            SupportedClientIdPrefix.X509SanDns(::validateChain),
            SupportedClientIdPrefix.X509Hash(::validateChain),
        ),
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.RS256),
        ),
        vpConfiguration = VPConfiguration(
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

    private fun genState(): String {
        return State().value
    }

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
                    "&dcql_query=$dcqlQuery" +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver().resolveRequestUri(authRequest)
            resolution.validateSuccess()
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
                    "&dcql_query=$dcqlQuery"

            val resolution = resolver().resolveRequestUri(authRequest)

            resolution.validateSuccess()
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
            val jwtClaimsSet = jwtClaimsSet(
                "Verifier",
                "https://eudi.netcompany-intrasoft.com/wallet/direct_post",
                unvalidatedClientMetaData,
            )

            val signedJwt = createSignedRequestJwt(jwkSet, jwtClaimsSet, typ)
            val authRequest =
                """
             http://localhost:8080/public_url?client_id=Verifier&request=$signedJwt
                """.trimIndent()

            val resolution = resolver().resolveRequestUri(authRequest)
            assertions(resolution)
        }

        test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
            it.validateSuccess()
        }

        listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
            .forEach { type ->
                test(type) {
                    it.validateInvalid<RequestValidationError.InvalidJarJwt>()
                }
            }
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_san_dns prefix`() = runTest {
        suspend fun test(typ: JOSEObjectType? = null, assertions: (Resolution) -> Unit) {
            val keyStore = KeyStore.getInstance("JKS")
            keyStore.load(
                load("certificates/certificates.jks"),
                "12345".toCharArray(),
            )
            val clientId = "x509_san_dns:verifier.example.gr"
            val jwtClaimsSet = jwtClaimsSet(
                clientId,
                "https://verifier.example.gr/wallet/direct_post",
                UnvalidatedClientMetaData(
                    jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                    vpFormatsSupported = VpFormatsSupported(
                        msoMdoc =
                            VpFormatsSupported.MsoMdoc(
                                issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                            ),
                    ),
                ),
            )
            val signedJwt = createSignedRequestJwt(keyStore, jwtClaimsSet, typ)
            val authRequest = "http://localhost:8080/public_url?client_id=$clientId&request=$signedJwt"

            val resolution = resolver().resolveRequestUri(authRequest)
            assertions(resolution)
        }

        test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
            it.validateSuccess()
        }

        listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
            .forEach { type ->
                test(type) {
                    it.validateInvalid<RequestValidationError.InvalidJarJwt>()
                }
            }
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_hash prefix`() = runTest {
        suspend fun test(typ: JOSEObjectType? = null, assertions: (Resolution) -> Unit) {
            val keyStore = KeyStore.getInstance("JKS")
            keyStore.load(
                load("certificates/certificates.jks"),
                "12345".toCharArray(),

            )
            val clientId = "x509_hash:0Wuix-gyx7KGtmfxusspetyYsnjThtGOpI15s5QVPZQ"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")
            val jwtClaimsSet = jwtClaimsSet(
                clientId,
                "https://verifier.example.gr",
                UnvalidatedClientMetaData(
                    jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                    vpFormatsSupported = VpFormatsSupported(
                        msoMdoc =
                            VpFormatsSupported.MsoMdoc(
                                issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                                deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                            ),
                    ),
                ),
            )
            val signedJwt = createSignedRequestJwt(keyStore, jwtClaimsSet, typ)
            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"

            val resolution = resolver().resolveRequestUri(authRequest)
            assertions(resolution)
        }

        test(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE)) {
            it.validateSuccess()
        }

        listOf(null, JOSEObjectType(""), JOSEObjectType("jwt"))
            .forEach { type ->
                test(type) {
                    it.validateInvalid<RequestValidationError.InvalidJarJwt>()
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
                "&dcql_query=$dcqlQuery" +
                "&client_metadata=$clientMetadataNoVpFormats"

        assertFailsWith<MissingFieldException> {
            resolver().resolveRequestUri(authRequest)
        }
    }

    @Test
    fun `if no common ground on wallet and verifier vp_formats resolution fails with ClientVpFormatsNotSupportedFromWallet`() = runTest {
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
                "&dcql_query=$dcqlQuery" +
                "&client_metadata=$clientMetadata"

        val resolution = resolver().resolveRequestUri(authRequest)
        resolution.validateInvalid<ResolutionError.ClientVpFormatsNotSupportedFromWallet>()
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
                "&dcql_query=$dcqlQuery" +
                "&client_metadata=$clientMetadata"

        val resolution = resolver().resolveRequestUri(authRequest)
        with(resolution.validateSuccess()) {
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
                "&dcql_query=$dcqlQuery"

        val resolution = resolver().resolveRequestUri(authRequest)
        val request = resolution.validateSuccess()

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
                "&dcql_query=$dcqlQuery" +
                "&client_metadata=$clientMetadata"

        val resolution = resolver().resolveRequestUri(authRequest)
        val request = resolution.validateSuccess()
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
        val request = resolution.validateSuccess()
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

    private fun createSignedRequestJwt(
        jwkSet: JWKSet,
        jwtClaimsSet: JWTClaimsSet,
        typ: JOSEObjectType?,
    ): String {
        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
        headerBuilder.keyID(jwkSet.keys[0].keyID)
        typ?.let {
            headerBuilder.type(it)
        }

        val signedJWT = SignedJWT(headerBuilder.build(), jwtClaimsSet)

        val signer = DefaultJWSSignerFactory().createJWSSigner(jwkSet.keys[0], JWSAlgorithm.RS256)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    private fun createSignedRequestJwt(
        keyStore: KeyStore,
        jwtClaimsSet: JWTClaimsSet,
        typ: JOSEObjectType?,
    ): String {
        val chain = keyStore.getCertificateChain("verifierexample")
        val base64EncodedChain = chain.map {
            com.nimbusds.jose.util.Base64.encode(it.encoded)
        }
        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
        headerBuilder.x509CertChain(base64EncodedChain.toMutableList())
        typ.let {
            headerBuilder.type(it)
        }

        val signedJWT = SignedJWT(headerBuilder.build(), jwtClaimsSet)

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

    private fun jwtClaimsSet(
        clientId: String,
        responseUri: String,
        clientMetadata: UnvalidatedClientMetaData,
    ): JWTClaimsSet {
        val query = Json.decodeFromStream<DCQL>(load("dcql/eudi_msomdoc_pid_dcql_query.json"))

        return with(JWTClaimsSet.Builder()) {
            audience("https://self-issued.me/v2")
            issueTime(Date())
            claim("client_id", clientId)
            claim("response_uri", responseUri)
            claim("response_type", "vp_token")
            claim("nonce", "nonce")
            claim("response_mode", "direct_post")
            claim(OpenId4VPSpec.DCQL_QUERY, Jackson.toJsonObject(query))
            claim("state", "638JwH0b2jrhGlAZQVa50KysVazkI-YpiFcLj2DLMalJpZK6XC22vAsPqXkpwAwXzfYpK-WLc3GhHYK8lbT6rw")
            claim("client_metadata", Jackson.toJsonObject(clientMetadata))
            build()
        }
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

            resolution.validateInvalid<RequestValidationError.UnsupportedResponseType>()
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

            resolution.validateInvalid<RequestValidationError.MissingNonce>()
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

            resolution.validateInvalid<RequestValidationError.MissingClientId>()
        }

        test(genState())
        test()
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun readFileAsText(fileName: String): String {
        return json.decodeFromStream<JsonObject>(load(fileName)).jsonObject.toString()
    }

    private fun validateChain(chain: List<X509Certificate>): Boolean {
        return try {
            for (i in chain.indices)
                if (i > 0) chain[i - 1].verify(chain[i].publicKey)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun load(f: String): InputStream =
        UnvalidatedRequestResolverTest::class.java.classLoader.getResourceAsStream(f) ?: error("File $f not found")

    private fun Resolution.validateSuccess(): ResolvedRequestObject =
        when (this) {
            is Resolution.Success -> requestObject
            is Resolution.Invalid -> fail("Invalid resolution found while expected success\n$error")
        }

    private inline fun <reified T : AuthorizationRequestError> Resolution.validateInvalid(): T =
        when (this) {
            is Resolution.Invalid -> assertIs(error, "${T::class} error expected")
            else -> fail("Success resolution found while expected Invalid")
        }

    @DisplayName("when using transaction_data")
    @Nested
    inner class TransactionDataTest {
        private val queryWithSingleCredential = BasicNameValuePair("dcql_query", readFileAsText("dcql/basic_example.json"))
        private val queryWithMultipleCredentials = BasicNameValuePair("dcql_query", readFileAsText("dcql/complex_example.json"))

        private suspend fun testAndThen(
            transactionData: JsonArray,
            query: NameValuePair,
            block: suspend (Resolution) -> Unit,
        ) {
            val state = genState()
            val clientMetadata = buildJsonObject {
                put("jwks", jwkSetJO)
                put("vp_formats_supported", vpFormatsJO)
            }
            val authorizationUrl = URIBuilder("https://client.example.org/universal-link")
                .addParameter("response_type", "vp_token")
                .addParameter("client_id", "redirect_uri:https://client.example.org/cb")
                .addParameter("redirect_uri", "https://client.example.org/cb")
                .addParameter("nonce", "n-0S6_WzA2Mj")
                .addParameter("state", state)
                .addParameter(query.name, query.value)
                .addParameter("client_metadata", clientMetadata.toString())
                .addParameter("transaction_data", jsonSupport.encodeToString(transactionData))
                .build()
            val resolution = resolver().resolveRequestUri(authorizationUrl.toString())
            block(resolution)
        }

        private suspend fun testAndThen(
            transactionData: JsonObject,
            query: NameValuePair,
            block: suspend (Resolution) -> Unit,
        ) {
            testAndThen(
                JsonArray(
                    listOf(
                        JsonPrimitive(
                            base64UrlNoPadding.encode(jsonSupport.encodeToString(transactionData).encodeToByteArray()),
                        ),
                    ),
                ),
                query,
                block,
            )
        }

        @Test
        fun `if transaction_data contains non base64url encoded values, resolution fails`() = runTest {
            val transactionData = JsonArray(listOf(JsonPrimitive("invalid")))
            testAndThen(transactionData, queryWithSingleCredential) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals("The pad bits must be zeros", cause.message)
            }
        }

        @Test
        fun `if transaction_data contains non JsonObject values, resolution fails`() = runTest {
            val transactionData = JsonArray(listOf(JsonPrimitive(base64UrlNoPadding.encode("foo".encodeToByteArray()))))
            testAndThen(transactionData, queryWithSingleCredential) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                    val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
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
                val request = it.validateSuccess()
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
                val request = it.validateSuccess()
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
                    val request = it.validateSuccess()
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
                val request = it.validateSuccess()
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
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Unsupported Transaction Data Format 'mso_mdoc'",
                    cause.message,
                )
            }
        }
    }
}

object Jackson {
    @PublishedApi
    internal val objectMapper: ObjectMapper by lazy { ObjectMapper() }

    inline fun <reified T> toJsonObject(value: T): Any = objectMapper.readValue<Any>(Json.encodeToString(value))
}
