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
package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestError
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.DispatcherOverDCApi
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.Jwt
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * Default implementation of [DispatcherOverDCApi]
 */
internal class DefaultDispatcherOverDCApi : DispatcherOverDCApi {

    override suspend fun assembleResponse(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters?,
    ): JsonObject {
        require(consensus is Consensus.NegativeConsensus || consensus is Consensus.PositiveConsensus) {
            "Invalid consensus. Expected either negative consensus or PositiveConsensus.VPTokenConsensus. " +
                "Actual consensus: ${consensus::class::simpleName}"
        }
        val response = request.responseWith(consensus, encryptionParameters)
        require(response is AuthorizationResponse.DCApi || response is AuthorizationResponse.DCApiJwt) {
            "Unsupported response mode: ${response::class.simpleName} for request coming from DC API channel"
        }
        return doAssemble(response)
    }

    override fun assembleErrorResponse(
        error: AuthorizationRequestError,
    ): JsonObject = buildJsonObject {
        val errorCode = AuthorizationRequestErrorCode.fromError(error)
        put("error", JsonPrimitive(errorCode.code))
    }

    private fun doAssemble(response: AuthorizationResponse): JsonObject = when (response) {
        is AuthorizationResponse.DCApi ->
            response.data.asJsonObject()

        is AuthorizationResponse.DCApiJwt -> buildJsonObject {
            put("response", JsonPrimitive(response.encryptData()))
        }
        else ->
            error("Unsupported authorization response ${response::class::simpleName} for dispatching over DC API")
    }

    private fun AuthorizationResponse.DCApiJwt.encryptData(): Jwt {
        val responseEncryptionSpecification = responseEncryptionSpecification
        requireNotNull(responseEncryptionSpecification) { "Response Encryption specification missing" }
        return responseEncryptionSpecification.encrypt(data)
    }
}
