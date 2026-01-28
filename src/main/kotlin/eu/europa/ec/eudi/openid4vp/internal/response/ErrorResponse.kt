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
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.ErrorDispatchDetails
import eu.europa.ec.eudi.openid4vp.ResponseMode

internal fun AuthorizationRequestError.responseWith(
    di: ErrorDispatchDetails,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponse {
    val payload = AuthorizationResponsePayload.InvalidRequest(
        error = this,
        state = di.state,
        nonce = di.nonce,
        clientId = di.clientId,
        encryptionParameters = encryptionParameters,
    )
    return responseWith(di, payload)
}

private fun responseWith(
    di: ErrorDispatchDetails,
    data: AuthorizationResponsePayload.InvalidRequest,
): AuthorizationResponse =
    when (val mode = di.responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(mode.responseURI, data)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(
            mode.responseURI,
            data,
            di.responseEncryptionSpecification,
        )

        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(mode.redirectUri, data)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(
            mode.redirectUri,
            data,
            di.responseEncryptionSpecification,
        )

        is ResponseMode.Query -> AuthorizationResponse.Query(mode.redirectUri, data)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(
            mode.redirectUri,
            data,
            di.responseEncryptionSpecification,
        )
    }
