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
package eu.europa.ec.eudi.openid4vp

/**
 * This interface assembles an appropriate authorization error response given an [error][AuthorizationRequestError]
 * that occurred during the authorization request resolution and then dispatches it to the verifier
 */
interface ErrorDispatcher {

    suspend fun dispatchError(
        error: AuthorizationRequestError,
        errorDispatchDetails: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome = when (errorDispatchDetails.responseMode) {
        is ResponseMode.DirectPost -> post(error, errorDispatchDetails, encryptionParameters)
        is ResponseMode.DirectPostJwt -> post(error, errorDispatchDetails, encryptionParameters)
        is ResponseMode.Query -> encodeRedirectURI(error, errorDispatchDetails, encryptionParameters)
        is ResponseMode.QueryJwt -> encodeRedirectURI(error, errorDispatchDetails, encryptionParameters)
        is ResponseMode.Fragment -> encodeRedirectURI(error, errorDispatchDetails, encryptionParameters)
        is ResponseMode.FragmentJwt -> encodeRedirectURI(error, errorDispatchDetails, encryptionParameters)
    }

    /**
     * Method forms a suitable authorization response, based on the [error] and the provided [errorDispatchDetails], then
     * post it to the Verifier's end-point and returns his response.
     *
     * This method is applicable when the [errorDispatchDetails] contains a [ErrorDispatchDetails.responseMode] which is
     * either [ResponseMode.DirectPost] or [ResponseMode.DirectPostJwt].
     *
     * @param error The error to dispatch
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     * @param errorDispatchDetails Details on how to dispatch the error
     * @return the verifier's response after receiving the authorization response.
     */
    suspend fun post(
        error: AuthorizationRequestError,
        errorDispatchDetails: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.VerifierResponse

    /**
     * Method forms a suitable authorization response, based on the [error] and the provided [errorDispatchDetails], and then
     * encodes this response to a URI.
     * To this URI, the wallet (caller) must redirect its authorization response
     *
     * This method is applicable when [errorDispatchDetails] contains a [ErrorDispatchDetails.responseMode] which is one of
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     *
     * @param error The error to dispatch
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     * @param errorDispatchDetails Details on how to dispatch the error
     * @return a URI pointing to the verifier to which the wallet(caller) must redirect its response. This URI carries
     * the authorization response
     */
    suspend fun encodeRedirectURI(
        error: AuthorizationRequestError,
        errorDispatchDetails: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.RedirectURI
}
