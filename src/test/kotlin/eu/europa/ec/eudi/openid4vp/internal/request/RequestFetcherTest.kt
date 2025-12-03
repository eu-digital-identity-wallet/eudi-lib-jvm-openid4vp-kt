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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig.Companion.SelfIssued
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import kotlin.test.*

internal class RequestFetcherTest {

    @Test
    fun `request uri method post - fetching fails on error`() = runTest {
        val issuer = "eudi_wallet"
        val clientId = "verifier"
        val jarEncryptionRequirement = EncryptionRequirement.NotRequired
        val config = config(issuer = issuer, clientId = clientId, jarEncryptionRequirement)
        val requestUri = URI.create("https://verifier/signed-request")

        val engine = MockEngine(requestUri, jarEncryptionRequirement) { encryptionKey, walletNonce ->
            assertNull(encryptionKey)
            respondBadRequest()
        }
        val client = createHttpClient(httpEngine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        val exception = assertFailsWith(AuthorizationRequestException::class) {
            fetcher.fetchRequest(request)
        }
        assertEquals(RequestValidationError.InvalidJarJwt("JAR JWT parse error"), exception.error)
    }

    @Test
    fun `request uri method post - fails on audience mismatch`() = runTest {
        val issuer = "eudi_wallet"
        val clientId = "verifier"
        val jarEncryptionRequirement = EncryptionRequirement.NotRequired
        val config = config(issuer = issuer, clientId = clientId, jarEncryptionRequirement)
        val requestUri = URI.create("https://verifier/signed-request")

        lateinit var signedRequest: SignedJWT
        val engine = MockEngine(requestUri, jarEncryptionRequirement) { encryptionKey, walletNonce ->
            assertNull(encryptionKey)

            signedRequest = createSignedRequestObject(audience = SelfIssued.value, clientId = clientId, walletNonce = walletNonce)

            respond(
                content = signedRequest.serialize(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
            )
        }
        val client = createHttpClient(httpEngine = engine)

        val fetcher = RequestFetcher(client, config)
        val exception = assertFailsWith(AuthorizationRequestException::class) {
            val request = UnvalidatedRequest.JwtSecured.PassByReference(
                clientId = clientId,
                jwtURI = requestUri.toURL(),
                requestURIMethod = RequestUriMethod.POST,
            )
            fetcher.fetchRequest(request)
        }
        assertEquals(
            RequestValidationError.InvalidJarJwt("JAR '${RFC7519.AUDIENCE}' mismatch. Expected: $issuer, found: ${SelfIssued.value}"),
            exception.error,
        )
    }

    @Test
    fun `request uri method post - fetch signed request object`() = runTest {
        val issuer = "eudi_wallet"
        val clientId = "verifier"
        val jarEncryptionRequirement = EncryptionRequirement.NotRequired
        val config = config(issuer = issuer, clientId = clientId, jarEncryptionRequirement)
        val requestUri = URI.create("https://verifier/signed-request")

        lateinit var signedRequest: SignedJWT
        val engine = MockEngine(requestUri, jarEncryptionRequirement) { encryptionKey, walletNonce ->
            assertNull(encryptionKey)

            signedRequest = createSignedRequestObject(audience = issuer, clientId = clientId, walletNonce = walletNonce)

            respond(
                content = signedRequest.serialize(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
            )
        }
        val client = createHttpClient(httpEngine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        val receivedRequest = assertIs<ReceivedRequest.Signed>(fetcher.fetchRequest(request))
        assertEquals(signedRequest.serialize(), receivedRequest.toSignedJwts()[0].serialize())
    }

    @Test
    fun `request uri method post - decryption fails when jar is not encrypted with jwk in jwks`() = runTest {
        val issuer = "eudi_wallet"
        val clientId = "verifier"
        val jarEncryptionRequirement = EncryptionRequirement.Required(
            supportedEncryptionAlgorithms = listOf(JWEAlgorithm.ECDH_ES_A256KW),
            supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
            ephemeralEncryptionKeyCurve = Curve.P_521,
        )
        val config = config(issuer = issuer, clientId = clientId, jarEncryptionRequirement)
        val requestUri = URI.create("https://verifier/encrypted-request")

        lateinit var signedRequest: SignedJWT
        val engine =
            MockEngine(requestUri, jarEncryptionRequirement) { encryptionKey, walletNonce ->
                assertNotNull(encryptionKey)
                signedRequest = createSignedRequestObject(audience = issuer, clientId = clientId, walletNonce = walletNonce)
                val encryptedRequest = createEncryptedRequestObject(
                    signedRequest,
                    ECKeyGenerator(jarEncryptionRequirement.ephemeralEncryptionKeyCurve).generate(),
                    jarEncryptionRequirement.supportedEncryptionAlgorithms.first(),
                    jarEncryptionRequirement.supportedEncryptionMethods.first(),
                )

                respond(
                    content = encryptedRequest.serialize(),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
                )
            }
        val client = createHttpClient(httpEngine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        assertFailsWith(JOSEException::class) {
            fetcher.fetchRequest(request)
        }
    }

    @Test
    fun `request uri method post - fetch encrypted and signed request object`() = runTest {
        val issuer = "eudi_wallet"
        val clientId = "verifier"
        val jarEncryptionRequirement = EncryptionRequirement.Required(
            supportedEncryptionAlgorithms = listOf(JWEAlgorithm.ECDH_ES_A256KW),
            supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
            ephemeralEncryptionKeyCurve = Curve.P_521,
        )
        val config = config(issuer = issuer, clientId = clientId, jarEncryptionRequirement)
        val requestUri = URI.create("https://verifier/encrypted-request")

        lateinit var signedRequest: SignedJWT
        val engine =
            MockEngine(requestUri, jarEncryptionRequirement) { encryptionKey, walletNonce ->
                assertNotNull(encryptionKey)
                signedRequest = createSignedRequestObject(audience = issuer, clientId = clientId, walletNonce = walletNonce)
                val encryptedRequest = createEncryptedRequestObject(
                    signedRequest,
                    encryptionKey,
                    jarEncryptionRequirement.supportedEncryptionAlgorithms.first(),
                    jarEncryptionRequirement.supportedEncryptionMethods.first(),
                )

                respond(
                    content = encryptedRequest.serialize(),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
                )
            }
        val client = createHttpClient(httpEngine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        val receivedRequest = assertIs<ReceivedRequest.Signed>(fetcher.fetchRequest(request))
        assertEquals(signedRequest.serialize(), receivedRequest.toSignedJwts()[0].serialize())
    }
}

private fun config(issuer: String, clientId: String, jarEncryptionRequirement: EncryptionRequirement): OpenId4VPConfig =
    OpenId4VPConfig(
        issuer = Issuer(issuer),
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Post(
                includeWalletMetadata = true,
                jarEncryption = jarEncryptionRequirement,
                useWalletNonce = NonceOption.Use(),
            ),
        ),
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        ),
        supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.Preregistered(PreregisteredClient(clientId, clientId))),
    )

private fun createSignedRequestObject(audience: String, clientId: String, walletNonce: String): SignedJWT =
    SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).build(),
        JWTClaimsSet.Builder()
            .audience(audience)
            .claim("client_id", clientId)
            .claim(OpenId4VPSpec.WALLET_NONCE, walletNonce)
            .build(),
    ).apply {
        sign(ECDSASigner(ECKeyGenerator(Curve.P_256).generate()))
    }

private fun createEncryptedRequestObject(
    signedRequestObject: SignedJWT,
    encryptionKey: ECKey,
    encryptionAlgorithm: JWEAlgorithm,
    encryptionMethod: EncryptionMethod,
): JWEObject =
    JWEObject(
        JWEHeader.Builder(encryptionAlgorithm, encryptionMethod)
            .contentType("JWT")
            .build(),
        Payload(signedRequestObject),
    ).apply {
        encrypt(ECDHEncrypter(encryptionKey))
    }

private fun MockEngine(
    requestUri: URI,
    jarEncryptionRequirement: EncryptionRequirement,
    handler: suspend MockRequestHandleScope.(ECKey?, String) -> HttpResponseData,
): MockEngine =
    MockEngine { request ->
        assertEquals(HttpMethod.Post, request.method)
        assertEquals(requestUri, request.url.toURI())
        assertEquals(listOf("application/oauth-authz-req+jwt", "application/jwt"), request.headers.getAll(HttpHeaders.Accept))

        val body = assertIs<FormDataContent>(request.body)
        val walletMetadata = Json.decodeFromString<JsonObject>(assertIs<String>(body.formData[OpenId4VPSpec.WALLET_METADATA]))

        val (encryptionAlgorithms, encryptionMethods, encryptionKeyCurve) =
            if (jarEncryptionRequirement is EncryptionRequirement.Required)
                Triple(
                    jarEncryptionRequirement.supportedEncryptionAlgorithms,
                    jarEncryptionRequirement.supportedEncryptionMethods,
                    jarEncryptionRequirement.ephemeralEncryptionKeyCurve,
                )
            else Triple(null, null, null)

        val encryptionKey = if (null != encryptionKeyCurve) {
            val jwks = assertIs<JsonObject>(walletMetadata["jwks"])
            val encryptionKeys = JWKSet.parse(Json.encodeToString(assertIs<JsonObject>(jwks)))
            assertEquals(1, encryptionKeys.size())
            val jwk = assertIs<ECKey>(encryptionKeys.keys.first())
            assertEquals(encryptionKeyCurve, jwk.curve)
            jwk
        } else {
            assertNull(walletMetadata["jwks"])
            null
        }

        if (null != encryptionAlgorithms) {
            assertEquals(
                JsonArray(encryptionAlgorithms.map { JsonPrimitive(it.name) }),
                walletMetadata["authorization_encryption_alg_values_supported"],
            )
        } else {
            assertNull(walletMetadata["authorization_encryption_alg_values_supported"])
        }

        if (null != encryptionMethods) {
            assertEquals(
                JsonArray(encryptionMethods.map { JsonPrimitive(it.name) }),
                walletMetadata["authorization_encryption_enc_values_supported"],
            )
        } else {
            assertNull(walletMetadata["authorization_encryption_enc_values_supported"])
        }

        val walletNonce = assertIs<String>(body.formData[OpenId4VPSpec.WALLET_NONCE])

        handler(encryptionKey, walletNonce)
    }
