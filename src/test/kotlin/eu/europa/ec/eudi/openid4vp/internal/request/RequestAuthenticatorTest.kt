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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.AbsoluteDIDUrl
import eu.europa.ec.eudi.openid4vp.internal.DID
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Clock
import kotlin.test.*

@DisplayName("In case of request is coming through HTTP")
class ClientAuthenticatorOverHTTPTest {

    @DisplayName("when handling a request")
    @Nested
    inner class ClientAuthenticatorCommonTest {

        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
            ),
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if client_id is missing, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = null).unsigned()
            assertFailsWithError<RequestValidationError.MissingClientId> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }

        @Test
        fun `if 'origin' is used as a client id prefix, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = "origin:test_client_id").unsigned()
            assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }
    }

    @DisplayName("when handling a request with `redirect_uri` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingRedirectUriTest {
        private val clientId = URI.create("https://localhost:8080")
        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
            ),
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if request is not signed, authentication succeeds`() =
            runTest {
                val request = UnvalidatedRequestObject(
                    clientId = "redirect_uri:$clientId",
                ).unsigned()

                val client = clientAuthenticator.authenticateClientOverHttp(request)
                assertEquals(AuthenticatedClient.RedirectUri(clientId), client)
            }

        @Test
        fun `if  request is signed, authentication fails`() = runTest {
            val (alg, key) = randomKey()
            val request = UnvalidatedRequestObject(
                clientId = "redirect_uri:$clientId",
            ).signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertEquals("RedirectUri cannot be used in signed request", error.value)
        }

        @Test
        fun `if  redirect_uri is insecure, authentication fails`() = runTest {
            val httpClientId = URI.create("http://localhost:8080")
            val request = UnvalidatedRequestObject(
                clientId = "redirect_uri:$httpClientId",
            ).unsigned()

            assertThrows<AuthorizationRequestException> { clientAuthenticator.authenticateClientOverHttp(request) }
        }
    }

    @DisplayName("when handling a request with pre-registered client")
    @Nested
    inner class ClientAuthenticatorWhenUsingPreRegisteredClientTest {
        private val algAndKey = randomKey()
        private val preRegisteredClient = PreregisteredClient(
            "testPreRegistered",
            "Test Pre-Registered Client",
            algAndKey.first to JWKSet(algAndKey.second.toPublicJWK()),
        )
        private val preRegisteredClientFooBar = PreregisteredClient(
            "foo:bar",
            "Pre-Registered Client with : in client_id",
            algAndKey.first to JWKSet(algAndKey.second.toPublicJWK()),
        )
        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
                SupportedClientIdPrefix.Preregistered(preRegisteredClient, preRegisteredClientFooBar),
            ),
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if request is signed by a pre-registered client, authentication succeeds`() =
            runTest {
                val (alg, key) = algAndKey
                val request = UnvalidatedRequestObject(
                    clientId = "testPreRegistered",
                ).signed(alg, key)

                val client = clientAuthenticator.authenticateClientOverHttp(request)
                assertEquals(AuthenticatedClient.Preregistered(preRegisteredClient), client)
            }

        @Test
        fun `if client_id contains colon char and is not one of the known prefixes, fallback to pre-registered client prefix`() =
            runTest {
                val (alg, key) = algAndKey
                val request = UnvalidatedRequestObject(
                    clientId = "foo:bar",
                ).signed(alg, key)

                val authenticateClient =
                    assertIs<AuthenticatedClient.Preregistered>(clientAuthenticator.authenticateClientOverHttp(request))
                assertEquals(preRegisteredClientFooBar, authenticateClient.preregisteredClient)
            }
    }

    @DisplayName("when handling a request with `decentralized_identifier` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingDIDTest {
        private val originalClientId = DID.parse("did:example:123").getOrThrow()
        private val clientId = "decentralized_identifier:$originalClientId"
        private val keyUrl = AbsoluteDIDUrl.parse("$originalClientId#01").getOrThrow()
        private val algAndKey = randomKey()
        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.DecentralizedIdentifier { url ->
                    assertEquals(keyUrl.uri, url)
                    algAndKey.second.toPublicKey()
                },
            ),
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = clientId,
        )

        @Test
        fun `if request is not signed, authentication fails`() = runTest {
            val request = requestObject.unsigned()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.value.endsWith("cannot be used in unsigned request")
            }
        }

        @Test
        fun `if kid JOSE HEADER is missing, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            // without kid JOSE Header
            val request = requestObject.signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.cause.startsWith("Missing kid")
            }
        }

        @Test
        fun `if kid JOSE HEADER is not a DID URL, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            // with a non DID URL kid JOSE Header
            val request = requestObject.signed(alg, key) { keyID("foo") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.cause.endsWith("kid should be DID URL")
            }
        }

        @Test
        fun `if kid JOSE HEADER is DID URL but not a sub-resource of client_id, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            // with irrelevant DID
            val request = requestObject.signed(alg, key) { keyID("did:foo:bar#1") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.cause.contains("kid should be DID URL sub-resource")
            }
        }

        @Test
        fun `if resolution fails, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            val failingResolution = LookupPublicKeyByDIDUrl { _ ->
                throw RuntimeException("Something happened")
            }
            val clientAuthenticator = ClientAuthenticator(
                cfg.copy(
                    supportedClientIdPrefixes = listOf(
                        SupportedClientIdPrefix.DecentralizedIdentifier(failingResolution),
                    ),
                ),
            )

            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            assertFailsWithError<RequestValidationError.DIDResolutionFailed> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }

        @Test
        fun `if resolution succeeds, authentication succeeds`() = runTest {
            val (alg, key) = algAndKey
            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            val client = clientAuthenticator.authenticateClientOverHttp(request)
            assertEquals(AuthenticatedClient.DecentralizedIdentifier(originalClientId, key.toPublicKey()), client)
        }
    }

    @DisplayName("when handling a request with `verifier_attestation` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingVerifierAttestationTest {

        private val clientId = "someClient"
        private val algAndKey = randomKey()

        private val cfg = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.VerifierAttestation(AttestationIssuer.verifier),
            ),
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = "verifier_attestation:$clientId",
        )

        @Test
        fun `if request is unsigned, authentication fails`() = runTest {
            val request = requestObject.unsigned()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.value.endsWith("cannot be used in unsigned request")
            }
        }

        @Test
        fun `if JAR is missing the jwt JOSE header, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            val request = requestObject.signed(alg, key)
            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue {
                error.cause.contains("Missing jwt JOSE Header")
            }
        }

        @Test
        fun `if JAR contains an attestation from a trusted issuer, authentication succeeds`() = runTest {
            val (alg, key) = algAndKey

            val verifierAttestation = AttestationIssuer.attestation(
                clock = cfg.clock,
                clientId = clientId,
                clientPubKey = key.toPublicJWK(),
            )
            val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)

            val client = clientAuthenticator.authenticateClientOverHttp(request)
            assertIs<AuthenticatedClient.VerifierAttestation>(client)
            assertEquals(clientId, client.clientId)
            assertEquals(AttestationIssuer.ID, client.claims.iss)
            assertEquals(clientId, client.claims.sub)
            assertEquals(key.toPublicJWK(), client.claims.verifierPubJwk)
        }

        @Test
        fun `if JAR contains an attestation from an untrusted issuer, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            val verifierAttestation = AttestationIssuer.attestation(
                clock = cfg.clock,
                clientId = clientId,
                clientPubKey = key.toPublicJWK(),
            )

            // Do not trust AttestationIssuer
            val notTrustingVerifier = object : JWSVerifier by AttestationIssuer.verifier {
                override fun verify(header: JWSHeader?, signingInput: ByteArray?, signature: Base64URL?): Boolean {
                    throw JOSEException("Fail")
                }
            }

            val clientAuthenticator = ClientAuthenticator(
                cfg.copy(
                    supportedClientIdPrefixes = listOf(
                        SupportedClientIdPrefix.VerifierAttestation(
                            notTrustingVerifier,
                        ),
                    ),
                ),
            )

            val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)
            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue { "Not trusted" in error.cause }
        }
    }
}

@DisplayName("In case of request is coming through DC API")
class RequestAuthenticatorOverDCApiTest {

    private val didAlgAndKey = randomKey()

    private val x509SanDnsSupportedPrefix = SupportedClientIdPrefix.X509SanDns({ _ -> true })
    private val didSupportedScheme = SupportedClientIdPrefix.DecentralizedIdentifier({ _ -> didAlgAndKey.second.toPublicKey() })

    private val cfg = OpenId4VPConfig(
        vpFormatsSupported = VpFormatsSupported(
            VpFormatsSupported.SdJwtVc.HAIP,
            VpFormatsSupported.MsoMdoc(
                issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
            ),
        ),
        supportedClientIdPrefixes = listOf(x509SanDnsSupportedPrefix, didSupportedScheme),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.Expect(ClientIdPrefix.DecentralizedIdentifier),
        ),
    )

    @DisplayName("when handling a request")
    @Nested
    inner class AuthenticatorCommonTest {

        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if request is unsinged the resolved client must be Origin`() = runTest {
            val request = UnvalidatedRequestObject().unsigned()

            val (authenticateClient, _) = clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            assertIs<AuthenticatedClient.Origin>(authenticateClient)
            assertTrue("test_origin" == authenticateClient.clientId)
        }
    }

    @DisplayName("when handling a multi-signed request")
    @Nested
    inner class ClientAuthenticatorMultiSignedRequestsTest {

        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if expected scheme is found request client is properly authenticated`() = runTest {
            val didAlgAndKey = randomKey()
            val request = UnvalidatedRequestObject(
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(didSigner(didAlgAndKey), verifierAttestationSigner(didAlgAndKey, cfg.clock)),
            )
            val (authenticateClient, _) = clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            assertIs<AuthenticatedClient.DecentralizedIdentifier>(authenticateClient)
        }

        @Test
        fun `if request expected scheme is not found in request fail`() = runTest {
            val didAlgAndKey = randomKey()
            val request = UnvalidatedRequestObject(
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(verifierAttestationSigner(didAlgAndKey, cfg.clock)),
            )
            assertFailsWithError<RequestValidationError.NoMatchingClientPrefixInMultiSignedRequest> {
                clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            }
        }

        @Test
        fun `can create a multi-signed request`() = runTest {
            val originalClientId = DID.parse("did:example:123").getOrThrow()

            // Create two signers with different keys
            val (alg1, key1) = randomKey()
            val (alg2, key2) = randomKey()

            val signer1 = SchemeSigner(alg1, key1) { keyID(originalClientId.toString()) }
            val signer2 = SchemeSigner(alg2, key2) { keyID(originalClientId.toString()) }

            // Create a request object with client ID and expected origins
            val clientId = "decentralized_identifier:$originalClientId"
            val request = UnvalidatedRequestObject(
                clientId = clientId,
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(listOf(signer1, signer2))

            // Verify that the request is a ReceivedRequest.Signed with a JwsJson.General
            assertIs<ReceivedRequest.MultiSigned>(request)
            assertIs<JwsJson.General>(request.jwsJson)

            // Verify that the JwsJson.General has two signatures
            val jwsJson = request.jwsJson
            assertEquals(2, jwsJson.signatures.size)

            // Verify that the signatures have the correct protected headers
            val signature1 = jwsJson.signatures[0]
            val signature2 = jwsJson.signatures[1]

            assertNotNull(signature1.protected)
            assertNotNull(signature2.protected)
        }
    }
}
//
// Support
//

fun randomKey(): Pair<JWSAlgorithm, ECKey> =
    JWSAlgorithm.ES256 to ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()

private inline fun <reified E : AuthorizationRequestError> assertFailsWithError(block: () -> Unit): E {
    val exception = assertThrows<AuthorizationRequestException>(block)
    return assertIs<E>(exception.error)
}

private fun UnvalidatedRequestObject.unsigned(): ReceivedRequest.Unsigned =
    ReceivedRequest.Unsigned(this)

private fun UnvalidatedRequestObject.signedWithAttestation(
    alg: JWSAlgorithm,
    key: JWK,
    attestation: SignedJWT,
): ReceivedRequest.Signed = signed(alg, key) {
    this.customParam("jwt", attestation.serialize())
}

private fun UnvalidatedRequestObject.signed(
    alg: JWSAlgorithm,
    key: JWK,
    headerCustomization: (JWSHeader.Builder).() -> Unit = {},
): ReceivedRequest.Signed {
    val header = with(JWSHeader.Builder(alg)) {
        type(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
        headerCustomization()
        build()
    }
    val claimsSet = toJWTClaimSet()
    val jwt = SignedJWT(header, claimsSet).apply {
        val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
        sign(signer)
    }
    return ReceivedRequest.Signed(jwt)
}
