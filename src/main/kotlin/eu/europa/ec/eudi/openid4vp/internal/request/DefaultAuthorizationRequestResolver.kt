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

import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.JwsJson.Companion.flatten
import eu.europa.ec.eudi.openid4vp.internal.decodePayloadAs
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByValue
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL

@Serializable
@JvmInline
internal value class VerifierInfoTO(val value: JsonArray) {
    init {
        require(value.isNotEmpty())
        require(value.all { it is JsonObject })
    }

    override fun toString(): String = value.toString()

    val values: List<JsonObject>
        get() = value.map { it.jsonObject }
}

@Serializable
@JvmInline
internal value class TransactionDataTO(val value: JsonArray) {
    init {
        require(value.isNotEmpty())
        require(value.all { it is JsonPrimitive && it.isString })
    }

    override fun toString(): String = value.toString()

    val values: List<String>
        get() = value.map { it.jsonPrimitive.content }
}

/**
 * The data of an OpenID4VP authorization request without any validation and regardless of the way they sent to the wallet.
 */
@Serializable
internal data class UnvalidatedRequestObject(
    @SerialName("client_metadata") val clientMetaData: JsonObject? = null,
    @SerialName(OpenId4VPSpec.NONCE) val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName(OpenId4VPSpec.RESPONSE_URI) val responseUri: String? = null,
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: JsonObject? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("scope") val scope: String? = null,
    @SerialName("state") val state: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: TransactionDataTO? = null,
    @SerialName(OpenId4VPSpec.VERIFIER_INFO) val verifierInfo: VerifierInfoTO? = null,
)

enum class RequestUriMethod {
    GET, POST
}

/**
 * OAUTH2 authorization request
 *
 * This is merely a data carrier structure that doesn't enforce any rules.
 */
internal sealed interface UnvalidatedRequest {

    data class Plain(val requestObject: UnvalidatedRequestObject) : UnvalidatedRequest

    /**
     * JWT Secured authorization request (JAR)
     */
    sealed interface JwtSecured : UnvalidatedRequest {
        /**
         * The <em>client_id</em> of the verifier
         */
        val clientId: String

        /**
         * A JAR passed by value
         */
        data class PassByValue(override val clientId: String, val jwt: Jwt) : JwtSecured

        /**
         * A JAR passed by reference
         */
        data class PassByReference(
            override val clientId: String,
            val jwtURI: URL,
            val requestURIMethod: RequestUriMethod?,
        ) : JwtSecured
    }

    companion object {

        /**
         * Convenient method for parsing a URI representing an OAUTH2 Authorization request.
         */
        fun make(uriStr: String): Result<UnvalidatedRequest> = runCatchingCancellable {
            val requestParams = with(URI.create(uriStr)) {
                toKtorUrl().parameters.toMap().mapValues { it.value.first() }
            }

            fun clientId(): String =
                requestParams["client_id"]
                    ?: throw RequestValidationError.MissingClientId.asException()

            val requestValue = requestParams["request"]
            val requestUriValue = requestParams["request_uri"]
            val requestUriMethod =
                requestParams["request_uri_method"]?.let { value ->
                    when (value) {
                        "get" -> RequestUriMethod.GET
                        "post" -> RequestUriMethod.POST
                        else -> throw RequestValidationError.InvalidRequestUriMethod.asException()
                    }
                }
            when {
                !requestValue.isNullOrEmpty() -> {
                    ensure(requestUriValue == null) {
                        RequestValidationError.InvalidUseOfBothRequestAndRequestUri.asException()
                    }
                    ensure(requestUriMethod == null) {
                        RequestValidationError.InvalidRequestUriMethod.asException()
                    }
                    PassByValue(clientId(), requestValue)
                }

                !requestUriValue.isNullOrEmpty() -> {
                    val requestUri = requestUriValue.asURL().getOrThrow()
                    PassByReference(clientId(), requestUri, requestUriMethod)
                }

                else -> notSecured(requestParams)
            }
        }

        /**
         * Populates a [Plain] from the request parameters of an authorization request
         */
        private fun notSecured(requestParams: Map<String, String?>): Plain {
            fun jsonObject(p: String): JsonObject? =
                requestParams[p]?.let { Json.parseToJsonElement(it).jsonObject }

            fun jsonArray(p: String): JsonArray? =
                requestParams[p]?.let { Json.parseToJsonElement(it).jsonArray }

            return Plain(
                UnvalidatedRequestObject(
                    responseType = requestParams["response_type"],
                    dcqlQuery = jsonObject(OpenId4VPSpec.DCQL_QUERY),
                    scope = requestParams["scope"],
                    nonce = requestParams["nonce"],
                    responseMode = requestParams["response_mode"],
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = requestParams["client_id"],
                    responseUri = requestParams[OpenId4VPSpec.RESPONSE_URI],
                    redirectUri = requestParams["redirect_uri"],
                    state = requestParams["state"],
                    transactionData = jsonArray(OpenId4VPSpec.TRANSACTION_DATA)?.let { TransactionDataTO(it) },
                    verifierInfo = jsonArray(OpenId4VPSpec.VERIFIER_INFO)?.let { VerifierInfoTO(it) },
                ),
            )
        }
    }
}

internal sealed interface ReceivedRequest {
    data class Unsigned(val requestObject: UnvalidatedRequestObject) : ReceivedRequest
    data class Signed(val jwsJson: JwsJson) : ReceivedRequest {
        companion object {
            operator fun invoke(signedJwt: SignedJWT): Signed = Signed(JwsJson.from(signedJwt).getOrThrow())
        }
    }
}

/**
 * Decomposes a Nimbus [SignedJWT] into [JwsJson].
 */
private fun JwsJson.Companion.from(signedJwt: SignedJWT): Result<JwsJson> = runCatchingCancellable {
    require(signedJwt.state == JWSObject.State.SIGNED) { "JWS is not signed" }
    val compactFormString =
        "${signedJwt.header.toBase64URL()}.${signedJwt.payload.toBase64URL()}.${signedJwt.signature}"
    JwsJson.from(compactFormString).getOrThrow()
}

internal fun ReceivedRequest.Signed.toSignedJwts(): List<SignedJWT> =
    jwsJson.flatten().map {
        SignedJWT.parse("${it.protected}.${it.payload}.${it.signature}")
    }

internal class DefaultAuthorizationRequestResolver(
    private val openId4VPConfig: OpenId4VPConfig,
    private val httpClient: HttpClient,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequestUri(uri: String): Resolution =
        with(httpClient) {
            resolveRequestUri(uri)
        }

    private suspend fun HttpClient.resolveRequestUri(uri: String): Resolution {
        val fetchedRequest =
            try {
                fetchRequest(uri)
            } catch (e: AuthorizationRequestException) {
                return Resolution.Invalid.nonDispatchable(e.error)
            }

        val authenticatedRequest =
            try {
                authenticateRequest(fetchedRequest)
            } catch (e: AuthorizationRequestException) {
                val dispatchDetails =
                    when (openId4VPConfig.errorDispatchPolicy) {
                        ErrorDispatchPolicy.AllClients -> dispatchDetailsOrNull(fetchedRequest, openId4VPConfig)
                        ErrorDispatchPolicy.OnlyAuthenticatedClients -> null
                    }
                return Resolution.Invalid(e.error, dispatchDetails)
            }

        val resolved =
            try {
                validateRequestObject(authenticatedRequest)
            } catch (e: AuthorizationRequestException) {
                val dispatchDetails = dispatchDetailsOrNull(authenticatedRequest.requestObject, openId4VPConfig)
                return Resolution.Invalid(e.error, dispatchDetails)
            }

        return Resolution.Success(resolved)
    }

    private fun validateRequestObject(authenticatedRequest: AuthenticatedRequest): ResolvedRequestObject {
        val requestValidator = RequestObjectValidator(openId4VPConfig)
        return requestValidator.validateRequestObject(authenticatedRequest)
    }

    private suspend fun HttpClient.fetchRequest(uri: String): ReceivedRequest {
        val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
        val requestFetcher = RequestFetcher(this, openId4VPConfig)
        return requestFetcher.fetchRequest(unvalidatedRequest)
    }

    private suspend fun HttpClient.authenticateRequest(receivedRequest: ReceivedRequest): AuthenticatedRequest {
        val requestAuthenticator = RequestAuthenticator(openId4VPConfig, this)
        return requestAuthenticator.authenticate(receivedRequest)
    }
}

/**
 * Creates an invalid resolution for errors that manifested while trying to authenticate a Client.
 */
private fun dispatchDetailsOrNull(
    fetchedRequest: ReceivedRequest,
    openId4VPConfig: OpenId4VPConfig,
): ErrorDispatchDetails? =
    when (fetchedRequest) {
        is ReceivedRequest.Signed -> dispatchDetailsOrNull(fetchedRequest.jwsJson, openId4VPConfig)
        is ReceivedRequest.Unsigned -> dispatchDetailsOrNull(fetchedRequest.requestObject, openId4VPConfig)
    }

/**
 * Creates an invalid resolution for errors that manifested while trying to resolve the metadata of the Client or while
 * trying to resolve the Authorization Request.
 *
 * Such errors are dispatchable when:
 * * the response mode does not require encryption
 * * the response mode requires encryption, and we have resolved Client metadata that contains encryption parameters compatible with
 * the configuration of the Wallet
 */
private fun dispatchDetailsOrNull(
    unvalidatedRequest: UnvalidatedRequestObject,
    openId4VPConfig: OpenId4VPConfig,
): ErrorDispatchDetails? {
    return unvalidatedRequest.responseMode()?.let { responseMode ->
        val responseEncryptionSpecification =
            unvalidatedRequest.responseEncryptionSpecification(openId4VPConfig, responseMode)
        ErrorDispatchDetails(
            responseMode = responseMode,
            nonce = unvalidatedRequest.nonce,
            state = unvalidatedRequest.state,
            clientId = unvalidatedRequest.clientId?.let { VerifierId.parse(it).getOrNull() },
            responseEncryptionSpecification = responseEncryptionSpecification.getOrNull(),
        )
    }
}

private fun UnvalidatedRequestObject.responseEncryptionSpecification(
    openId4VPConfig: OpenId4VPConfig,
    responseMode: ResponseMode,
): Result<ResponseEncryptionSpecification?> = runCatchingCancellable {
    clientMetaData?.let {
        val decodeFromJsonElement = jsonSupport.decodeFromJsonElement<UnvalidatedClientMetaData>(clientMetaData)
        val validatedClientMetadata = decodeFromJsonElement.let {
            ClientMetaDataValidator.validateClientMetaData(
                it,
                responseMode,
                null,
                openId4VPConfig.responseEncryptionConfiguration,
                openId4VPConfig.vpConfiguration.vpFormatsSupported,
            )
        }
        validatedClientMetadata.responseEncryptionSpecification
    }
}

private fun UnvalidatedRequestObject.responseMode(): ResponseMode? {
    fun UnvalidatedRequestObject.responseUri(): URL? =
        responseUri?.let {
            runCatchingCancellable { URL(it) }.getOrNull()
        }

    fun UnvalidatedRequestObject.redirectUri(): URI? =
        redirectUri?.let {
            runCatchingCancellable { URI.create(it) }.getOrNull()
        }

    return when (responseMode) {
        "direct_post" -> responseUri()?.let { ResponseMode.DirectPost(it) }
        "direct_post.jwt" -> responseUri()?.let { ResponseMode.DirectPostJwt(it) }
        "query" -> redirectUri()?.let { ResponseMode.Query(it) }
        "query.jwt" -> redirectUri()?.let { ResponseMode.QueryJwt(it) }
        null, "fragment" -> redirectUri()?.let { ResponseMode.Fragment(it) }
        "fragment.jwt" -> redirectUri()?.let { ResponseMode.FragmentJwt(it) }
        else -> null
    }
}

private fun dispatchDetailsOrNull(
    jwsJson: JwsJson,
    openId4VPConfig: OpenId4VPConfig,
): ErrorDispatchDetails? =
    runCatchingCancellable {
        dispatchDetailsOrNull(
            jwsJson.decodePayloadAs<UnvalidatedRequestObject>(),
            openId4VPConfig,
        )
    }.getOrNull()

private fun URI.toKtorUrl(): Url = URLBuilder().takeFrom(this.toString()).build()
