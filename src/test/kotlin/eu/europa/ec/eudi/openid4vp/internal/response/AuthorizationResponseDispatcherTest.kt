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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingResponseType
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingScope
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURI
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.response.AuthorizationRequestErrorCode.INVALID_REQUEST_URI_METHOD
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.put
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import java.io.InputStream
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class AuthorizationResponseDispatcherTest {
    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val walletConfig = OpenId4VPConfig(
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
        clock = Clock.systemDefaultZone(),
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
            supportedAlgorithms = listOf(Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm),
            supportedMethods = listOf(EncryptionMethod.A256GCM),
        ),
    )

    private val clientMetadataStr =
        """
            {
                "jwks": {
                    "keys": [
                        {
                            "kty": "RSA",
                            "e": "AQAB",
                            "use": "sig",
                            "kid": "a4e1bbe6-26e8-480b-a364-f43497894453",
                            "iat": 1683559586,
                            "n": "xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew"
                        }
                    ]
                },
                "vp_formats_supported": {
                    "mso_mdoc": {
                        "issuerauth_alg_values": [-7, -9],
                        "deviceauth_alg_values": [-7, -9]
                    }
                }
            }
        """.trimIndent()

    private val clientMetaData = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
    private fun genState(): String {
        return State().value
    }

    @Test
    fun `dispatch vp_token with direct post`() = runTest {
        fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow())
            val query = Json.decodeFromStream<DCQL>(checkNotNull(load("dcql/mDL-example.json")))
            val validated = assertDoesNotThrow {
                ClientMetaDataValidator.validateClientMetaData(
                    clientMetaData,
                    responseMode,
                    query,
                    walletConfig.responseEncryptionConfiguration,
                    walletConfig.vpConfiguration.vpFormatsSupported,
                )
            }

            val openId4VPAuthRequestObject =
                ResolvedRequestObject(
                    responseEncryptionSpecification = validated.responseEncryptionSpecification,
                    vpFormatsSupported = VpFormatsSupported(
                        msoMdoc = VpFormatsSupported.MsoMdoc(
                            issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                            deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        ),
                    ),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    query = query,
                    transactionData = null,
                    verifierInfo = null,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus(
                VerifiablePresentations(
                    mapOf(
                        QueryId("query_0") to listOf(VerifiablePresentation.Generic("vp_token")),
                    ),
                ),
            )

            testApplication {
                externalServices {
                    hosts("https://respond.here") {
                        install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                            json()
                        }
                        routing {
                            post("/") {
                                val formParameters = call.receiveParameters()
                                val vpTokenTxt = formParameters["vp_token"].toString()
                                val stateParam = formParameters["state"]

                                assertEquals(
                                    "application/x-www-form-urlencoded",
                                    call.request.headers["Content-Type"],
                                )
                                assertEquals(state, stateParam)
                                assertEquals(vpTokenTxt, "{\"query_0\":[\"vp_token\"]}")

                                call.respond(buildJsonObject { put("redirect_uri", "https://foo") })
                            }
                        }
                    }
                }
                val managedHttpClient = createClient {
                    install(ContentNegotiation) {
                        json()
                    }
                }

                val dispatcher = DefaultDispatcher(managedHttpClient)
                val outcome = dispatcher.dispatch(
                    openId4VPAuthRequestObject,
                    vpTokenConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                assertIs<DispatchOutcome.VerifierResponse>(outcome)
            }
        }

        test(genState())
        test()
    }

    @Nested
    @DisplayName("Dispatch error")
    inner class ErrorDispatch {

        @Test
        fun `with direct post`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = null,
                )

                testApplication {
                    externalServices {
                        hosts("https://respond.here") {
                            install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                                json()
                            }
                            routing {
                                post("/") {
                                    val formParameters = call.receiveParameters()
                                    val errorTxt = formParameters["error"].toString()
                                    val stateParam = formParameters["state"]

                                    assertEquals(
                                        "application/x-www-form-urlencoded",
                                        call.request.headers["Content-Type"],
                                    )
                                    assertEquals(state, stateParam)
                                    assertEquals(AuthorizationRequestErrorCode.INVALID_CLIENT.code, errorTxt)

                                    call.respond(buildJsonObject { put("redirect_uri", "https://foo") })
                                }
                            }
                        }
                    }
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        RequestValidationError.InvalidClientId,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.VerifierResponse.Accepted>(outcome)
                    assertNotNull(outcome.redirectURI)
                }
            }

            test(genState())
            test()
        }

        @Test
        fun `with direct post jwt`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = ResponseEncryptionSpecification(
                        encryptionAlgorithm = Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm,
                        encryptionMethod = EncryptionMethod.parse(
                            Verifier.metaDataRequestingEncryptedResponse.responseEncryptionMethodsSupported.orEmpty()
                                .first(),
                        ),
                        recipientKey = Verifier.responseEncryptionKeyPair.toPublicJWK(),
                    ),
                )

                testApplication {
                    externalServices {
                        hosts("https://respond.here") {
                            install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                                json()
                            }
                            routing {
                                post("/") {
                                    val formParameters = call.receiveParameters()
                                    val responseJwt = formParameters["response"].toString()

                                    val claims = parseJwt(responseJwt)

                                    assertEquals(INVALID_REQUEST_URI_METHOD.code, claims["error"])
                                    assertEquals(state, claims["state"])

                                    assertEquals(
                                        "application/x-www-form-urlencoded",
                                        call.request.headers["Content-Type"],
                                    )

                                    call.respond(buildJsonObject { put("redirect_uri", "https://foo") })
                                }
                            }
                        }
                    }
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        RequestValidationError.InvalidRequestUriMethod,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.VerifierResponse.Accepted>(outcome)
                    assertNotNull(outcome.redirectURI)
                }
            }

            test(genState())
            test()
        }

        @Test
        fun `with query`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.Query("https://respond.here".asURI().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = null,
                )

                testApplication {
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        RequestValidationError.MissingResponseType,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.RedirectURI>(outcome)

                    val urlParams = Url(outcome.value).parameters
                    assertEquals(AuthorizationRequestErrorCode.INVALID_REQUEST.code, urlParams["error"])
                    assertEquals(state, urlParams["state"])
                }
            }

            test(genState())
            test()
        }

        @Test
        fun `with query jwt`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.QueryJwt("https://respond.here".asURI().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = ResponseEncryptionSpecification(
                        encryptionAlgorithm = Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm,
                        encryptionMethod = EncryptionMethod.parse(
                            Verifier.metaDataRequestingEncryptedResponse.responseEncryptionMethodsSupported.orEmpty()
                                .first(),
                        ),
                        recipientKey = Verifier.responseEncryptionKeyPair.toPublicJWK(),
                    ),
                )

                testApplication {
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        MissingScope,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.RedirectURI>(outcome)
                    val urlParams = Url(outcome.value).parameters
                    val responseJwt = urlParams["response"]
                    assertNotNull(responseJwt)
                    val claims = parseJwt(responseJwt)
                    assertEquals(AuthorizationRequestErrorCode.INVALID_REQUEST.code, claims["error"])
                    assertEquals(state, claims["state"])
                }
            }

            test(genState())
            test()
        }

        @Test
        fun `with fragment`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.Fragment("https://respond.here".asURI().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = null,
                )

                testApplication {
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        MissingResponseType,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.RedirectURI>(outcome)
                    val urlParams = Url(outcome.value).fragment.parseUrlEncodedParameters()
                    assertEquals("invalid_request", urlParams["error"])
                    assertEquals(state, urlParams["state"])
                }
            }

            test(genState())
            test()
        }

        @Test
        fun `with fragment jwt`() = runTest {
            fun test(state: String? = null) {
                val errorDispatchDetails = ErrorDispatchDetails(
                    responseMode = ResponseMode.FragmentJwt("https://respond.here".asURI().getOrThrow()),
                    state = state,
                    nonce = null,
                    clientId = null,
                    responseEncryptionSpecification = ResponseEncryptionSpecification(
                        encryptionAlgorithm = Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm,
                        encryptionMethod = EncryptionMethod.parse(
                            Verifier.metaDataRequestingEncryptedResponse.responseEncryptionMethodsSupported.orEmpty()
                                .first(),
                        ),
                        recipientKey = Verifier.responseEncryptionKeyPair.toPublicJWK(),
                    ),
                )

                testApplication {
                    val managedHttpClient = createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }

                    val dispatcher = DefaultDispatcher(managedHttpClient)
                    val outcome = dispatcher.dispatchError(
                        RequestValidationError.MissingResponseUri,
                        errorDispatchDetails,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )
                    assertIs<DispatchOutcome.RedirectURI>(outcome)
                    val urlParams = Url(outcome.value).fragment.parseUrlEncodedParameters()
                    val responseJwt = urlParams["response"]
                    assertNotNull(responseJwt)
                    val claims = parseJwt(responseJwt)
                    assertEquals("invalid_request", claims["error"])
                    assertEquals(state, claims["state"])
                }
            }

            test(genState())
            test()
        }

        private fun parseJwt(jwt: String): MutableMap<String, Any> {
            val encryptedJwt = EncryptedJWT.parse(jwt)
            val decrypter = ECDHDecrypter(Verifier.responseEncryptionKeyPair)
            encryptedJwt.decrypt(decrypter)
            assert(JWEObject.State.DECRYPTED == encryptedJwt.state)
            return encryptedJwt.jwtClaimsSet.claims
        }
    }

    private fun load(f: String): InputStream? =
        AuthorizationResponseDispatcherTest::class.java.classLoader.getResourceAsStream(f)
}
