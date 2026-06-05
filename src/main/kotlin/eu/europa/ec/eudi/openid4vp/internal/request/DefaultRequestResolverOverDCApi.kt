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

import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest.Signed
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest.Unsigned
import io.ktor.client.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonPrimitive

internal enum class DCApiExchangeProtocol {
    UNSIGNED,
    SIGNED,
    MULTISIGNED,
    ;

    companion object {
        fun from(protocol: String): DCApiExchangeProtocol =
            when (protocol) {
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED -> UNSIGNED
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED -> SIGNED
                OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED -> MULTISIGNED
                else -> throw ResolutionError.UnsupportedDcApiExchangeProtocol.asException()
            }
    }
}

internal class DefaultRequestResolverOverDCApi(
    private val openId4VPConfig: OpenId4VPConfig,
    private val httpClient: HttpClient,
) : AuthorizationRequestOverDCApiResolver {

    override suspend fun resolveRequestObject(protocol: String, origin: String, requestData: JsonObject): Resolution =
        with(httpClient) {
            this.resolveRequestObject(protocol, origin, requestData)
        }

    private suspend fun HttpClient.resolveRequestObject(protocol: String, origin: String, requestData: JsonObject): Resolution {
        try {
            val receivedRequest = ReceivedRequest.make(requestData).getOrThrow()
            val exchangeProtocol = DCApiExchangeProtocol.from(protocol)

            exchangeProtocol assertMatches receivedRequest

            val authenticatedRequest = authenticateRequest(origin, receivedRequest)
            val resolved = validateRequestObject(origin, authenticatedRequest, receivedRequest is Signed)

            return Resolution.Success(resolved)
        } catch (e: AuthorizationRequestException) {
            return Resolution.Invalid(e.error, null)
        }
    }

    private suspend fun HttpClient.authenticateRequest(origin: String, receivedRequest: ReceivedRequest): AuthenticatedRequest {
        val requestAuthenticator = RequestAuthenticator(openId4VPConfig, this)
        return requestAuthenticator.authenticateRequestOverDCApi(origin, receivedRequest)
    }

    private fun validateRequestObject(
        origin: String,
        authenticatedRequest: AuthenticatedRequest,
        isSigned: Boolean,
    ): ResolvedRequestObject {
        val requestValidator = RequestObjectValidator(openId4VPConfig)
        return requestValidator.validateDCApiRequestObject(origin, authenticatedRequest, isSigned)
    }

    private fun ReceivedRequest.Companion.make(requestData: JsonObject): Result<ReceivedRequest> = runCatching {
        val requestValue = requestData["request"]
        when {
            requestValue != null && requestValue is JsonObject -> {
                val jwsJson = jsonSupport.decodeFromJsonElement<JwsJson>(requestValue)
                Signed(jwsJson)
            }

            requestValue != null && requestValue is JsonPrimitive -> {
                val jwsJson = JwsJson.from(requestValue.jsonPrimitive.content).getOrThrow()
                Signed(jwsJson)
            }

            else -> Unsigned(jsonSupport.decodeFromJsonElement(requestData))
        }
    }
}

private infix fun DCApiExchangeProtocol.assertMatches(receivedRequest: ReceivedRequest) = when (this) {
    DCApiExchangeProtocol.UNSIGNED ->
        ensure(receivedRequest is Unsigned) {
            asMissMatchException(
                "Exchange protocol is ${OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_UNSIGNED} but request is not Unsigned.",
            )
        }

    DCApiExchangeProtocol.SIGNED ->
        ensure(receivedRequest is Signed && receivedRequest.jwsJson is JwsJson.Flattened) {
            asMissMatchException(
                "Exchange protocol is ${OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED} but request's format is not JWS " +
                    "compact serialization.",
            )
        }

    DCApiExchangeProtocol.MULTISIGNED ->
        ensure(receivedRequest is Signed && receivedRequest.jwsJson is JwsJson.General) {
            asMissMatchException(
                "Exchange protocol is ${OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED} but request's format is not " +
                    "JWS general serialization.",
            )
        }
}

private fun asMissMatchException(reason: String): Throwable =
    ResolutionError.DcApiExchangeProtocolNotMatchesReceivedRequest(reason).asException()
