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
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest.*
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

internal class DefaultRequestResolverOverDCApi private constructor(
    private val requestAuthenticator: RequestAuthenticator,
    private val requestObjectValidator: RequestObjectValidator,
) : AuthorizationRequestOverDCApiResolver {

    override suspend fun resolveRequestObject(protocol: String, origin: String, requestData: JsonObject): Resolution =
        try {
            val receivedRequest = makeReceivedRequest(requestData)
            val exchangeProtocol = DCApiExchangeProtocol.from(protocol)

            exchangeProtocol assertMatches receivedRequest

            val authenticatedRequest = requestAuthenticator.authenticateRequestOverDCApi(origin, receivedRequest)
            val resolved = requestObjectValidator.validateDCApiRequestObject(origin, authenticatedRequest, receivedRequest.isSigned)

            Resolution.Success(resolved)
        } catch (e: AuthorizationRequestException) {
            Resolution.Invalid(e.error, null)
        }

    private fun makeReceivedRequest(requestData: JsonObject): ReceivedRequest {
        val requestValue = requestData["request"]
        return when {
            requestValue != null && requestValue is JsonObject -> {
                val jwsJson = jsonSupport.decodeFromJsonElement<JwsJson.General>(requestValue)
                MultiSigned(jwsJson)
            }

            requestValue != null && requestValue is JsonPrimitive -> {
                val jwsJson = JwsJson.fromCompact(requestValue.jsonPrimitive.content).getOrThrow()
                Signed(jwsJson)
            }

            else -> Unsigned(jsonSupport.decodeFromJsonElement(requestData))
        }
    }

    companion object {
        operator fun invoke(
            openId4VPConfig: OpenId4VPConfig,
        ): DefaultRequestResolverOverDCApi = DefaultRequestResolverOverDCApi(
            requestAuthenticator = RequestAuthenticator(openId4VPConfig),
            requestObjectValidator = RequestObjectValidator(openId4VPConfig),
        )
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
        ensure(receivedRequest is Signed) {
            asMissMatchException(
                "Exchange protocol is ${OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_SIGNED} but request's format is not JWS " +
                    "compact serialization.",
            )
        }

    DCApiExchangeProtocol.MULTISIGNED ->
        ensure(receivedRequest is MultiSigned) {
            asMissMatchException(
                "Exchange protocol is ${OpenId4VPSpec.DC_API_EXCHANGE_PROTOCOL_MULTISIGNED} but request's format is not " +
                    "JWS general serialization.",
            )
        }
}

private fun asMissMatchException(reason: String): Throwable =
    ResolutionError.DcApiExchangeProtocolNotMatchesReceivedRequest(reason).asException()
