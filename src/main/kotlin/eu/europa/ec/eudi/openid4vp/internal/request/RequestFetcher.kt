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

import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig.Companion.SelfIssued
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URL
import java.text.ParseException

internal class RequestFetcher(
    private val httpClient: HttpClient,
    private val openId4VPConfig: OpenId4VPConfig,
) {
    /**
     * Fetches the authorization request, if needed
     */
    suspend fun fetchRequest(request: UnvalidatedRequest): ReceivedRequest = when (request) {
        is UnvalidatedRequest.Plain -> ReceivedRequest.Unsigned(request.requestObject)
        is UnvalidatedRequest.JwtSecured -> {
            val (jwt, walletNonce, audience) = when (request) {
                is UnvalidatedRequest.JwtSecured.PassByValue -> Triple(request.jwt, null, SelfIssued.value)
                is UnvalidatedRequest.JwtSecured.PassByReference -> fetchJwtWalletNonceAndAudience(request)
            }
            with(openId4VPConfig) {
                ensureValid(expectedClient = request.clientId, walletNonce, expectedAudience = audience, unverifiedJwt = jwt)
            }
        }
    }

    private suspend fun fetchJwtWalletNonceAndAudience(
        request: UnvalidatedRequest.JwtSecured.PassByReference,
    ): Triple<Jwt, Nonce?, String> {
        val (_, requestUri, requestUriMethod) = request

        val supportedMethods =
            openId4VPConfig.jarConfiguration.supportedRequestUriMethods

        return when (requestUriMethod) {
            null, RequestUriMethod.GET -> {
                ensure(supportedMethods.isGetSupported()) {
                    unsupportedRequestUriMethod(RequestUriMethod.GET)
                }
                Triple(httpClient.getJAR(requestUri), null, SelfIssued.value)
            }

            RequestUriMethod.POST -> {
                val postOptions =
                    ensureNotNull(supportedMethods.isPostSupported()) {
                        unsupportedRequestUriMethod(RequestUriMethod.POST)
                    }
                val walletNonce =
                    when (val nonceOption = postOptions.useWalletNonce) {
                        is NonceOption.Use -> Nonce(nonceOption.byteLength)
                        NonceOption.DoNotUse -> null
                    }
                val ephemeralJarEncryptionKey = when (val jarEncryption = postOptions.jarEncryption) {
                    EncryptionRequirement.NotRequired -> null
                    is EncryptionRequirement.Required -> jarEncryption.ephemeralEncryptionKey()
                }
                val walletMetaData =
                    if (postOptions.includeWalletMetadata) {
                        walletMetaData(openId4VPConfig, listOfNotNull(ephemeralJarEncryptionKey))
                    } else null

                val jwt = httpClient.postForJAR(requestUri, walletNonce, walletMetaData)
                val signedJwt = if (null != ephemeralJarEncryptionKey) {
                    jwt.decrypt(ephemeralJarEncryptionKey).getOrThrow()
                } else jwt

                val audience =
                    if (null != walletMetaData) openId4VPConfig.issuer.value
                    else SelfIssued.value

                Triple(signedJwt, walletNonce, audience)
            }
        }
    }
}

private fun OpenId4VPConfig.ensureValid(
    expectedClient: String,
    expectedWalletNonce: Nonce?,
    expectedAudience: String,
    unverifiedJwt: Jwt,
): ReceivedRequest.Signed {
    val signedJwt = ensureIsSignedJwt(unverifiedJwt).also(::ensureSupportedSigningAlgorithm)
    ensureSameClientId(expectedClient, signedJwt)
    if (expectedWalletNonce != null) {
        ensureSameWalletNonce(expectedWalletNonce, signedJwt)
    }
    ensureSameAudience(expectedAudience, signedJwt)
    return ReceivedRequest.Signed(signedJwt)
}

private fun ensureIsSignedJwt(unverifiedJwt: Jwt): SignedJWT =
    try {
        SignedJWT.parse(unverifiedJwt)
    } catch (_: ParseException) {
        throw invalidJwt("JAR JWT parse error")
    }

private fun ensureSameWalletNonce(expectedWalletNonce: Nonce, signedJwt: SignedJWT) {
    val walletNonce = signedJwt.jwtClaimsSet.getStringClaim(OpenId4VPSpec.WALLET_NONCE)
    ensure(expectedWalletNonce.toString() == walletNonce) {
        invalidJwt("Mismatch of wallet_nonce. Expected $expectedWalletNonce, actual $walletNonce")
    }
}

private fun OpenId4VPConfig.ensureSupportedSigningAlgorithm(signedJwt: SignedJWT) {
    val signingAlg = ensureNotNull(signedJwt.header.algorithm) {
        invalidJwt("JAR is missing alg claim from header")
    }
    ensure(signingAlg in jarConfiguration.supportedAlgorithms) {
        invalidJwt("JAR is signed with ${signingAlg.name} which is not supported")
    }
}

private fun ensureSameClientId(
    expectedClientId: String,
    signedJwt: SignedJWT,
): String {
    val jarClientId = signedJwt.jwtClaimsSet.getStringClaim("client_id")
    ensure(expectedClientId == jarClientId) {
        invalidJwt("ClientId mismatch. JAR request $expectedClientId, jwt $jarClientId")
    }
    return expectedClientId
}

private fun invalidJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

private fun unsupportedRequestUriMethod(m: RequestUriMethod): AuthorizationRequestException =
    RequestValidationError.UnsupportedRequestUriMethod(m).asException()

private const val APPLICATION_JWT = "application/jwt"
private const val APPLICATION_OAUTH_AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt"

private suspend fun HttpClient.getJAR(requestUri: URL): Jwt =
    try {
        get(requestUri) { addAcceptContentTypeJwt() }.body()
    } catch (e: ClientRequestException) {
        throw ResolutionError.UnableToFetchRequestObject(e).asException()
    }

private suspend fun HttpClient.postForJAR(
    requestUri: URL,
    walletNonce: Nonce?,
    walletMetaData: JsonObject?,
): Jwt {
    val form =
        parameters {
            walletNonce?.let { append(OpenId4VPSpec.WALLET_NONCE, it.toString()) }
            walletMetaData?.let { append(OpenId4VPSpec.WALLET_METADATA, Json.encodeToString(it)) }
        }
    return try {
        submitForm(requestUri.toString(), form) { addAcceptContentTypeJwt() }.body<Jwt>()
    } catch (e: ClientRequestException) {
        throw ResolutionError.UnableToFetchRequestObject(e).asException()
    }
}

private fun HttpRequestBuilder.addAcceptContentTypeJwt() {
    accept(ContentType.parse(APPLICATION_OAUTH_AUTHZ_REQ_JWT))
    accept(ContentType.parse(APPLICATION_JWT))
}

private const val CONTENT_TYPE_JWT = "JWT"

private fun Jwt.decrypt(recipientKey: ECKey): Result<Jwt> = runCatchingCancellable {
    val jwe = JWEObject.parse(this)
    require(CONTENT_TYPE_JWT == jwe.header.contentType) { "JWEObject must contain a JWT Payload" }

    val decrypter = ECDHDecrypter(recipientKey)
    jwe.decrypt(decrypter)
    val payload = jwe.payload

    payload.toString()
}

internal suspend fun EncryptionRequirement.Required.ephemeralEncryptionKey(): ECKey =
    withContext(Dispatchers.IO) {
        ECKeyGenerator(ephemeralEncryptionKeyCurve)
            .keyUse(KeyUse.ENCRYPTION)
            .generate()
    }

private fun ensureSameAudience(expectedAudience: String, signedJwt: SignedJWT) {
    val jwtAudience = signedJwt.jwtClaimsSet.audience
    ensure(!jwtAudience.isNullOrEmpty()) {
        invalidJwt("JAR is missing '${RFC7519.AUDIENCE}'")
    }
    ensure(1 == jwtAudience.size) {
        invalidJwt("JAR contains more than one values in '${RFC7519.AUDIENCE}'")
    }
    ensure(expectedAudience == jwtAudience.first()) {
        invalidJwt("JAR '${RFC7519.AUDIENCE}' mismatch. Expected: $expectedAudience, found: ${jwtAudience.first()}")
    }
}
