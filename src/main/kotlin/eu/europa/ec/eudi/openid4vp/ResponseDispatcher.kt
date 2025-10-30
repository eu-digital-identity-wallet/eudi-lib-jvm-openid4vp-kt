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
package eu.europa.ec.eudi.openid4vp

import java.net.URI

/**
 * Representation of holder's consensus to
 * a [ResolvedRequestObject]
 */
sealed interface Consensus : java.io.Serializable {

    /**
     * No consensus. Holder decided to reject
     * the request
     */
    data object NegativeConsensus : Consensus {
        private fun readResolve(): Any = NegativeConsensus
    }

    /**
     * Positive consensus. Holder decided to respond to the request.
     * The wallet has claims that fulfill Verifier's query, and the holder has chosen the claims to include.
     *
     * @property verifiablePresentations the Verifiable Presentations to be included in the authorization response
     */
    data class PositiveConsensus(val verifiablePresentations: VerifiablePresentations) : Consensus
}

/**
 * The outcome of dispatching an [Consensus] to
 * verifier/RP.
 */
sealed interface DispatchOutcome : java.io.Serializable {

    /**
     * In case verifier requested response to be redirected to a URI,
     * this class contains this URI with the response encoded to it
     */
    data class RedirectURI(val value: URI) : DispatchOutcome

    /**
     * In case verifier requested that response should be posted (direct post or direct post jwt)
     * this class contains the response of the verifier after receiving the authorization response
     */
    sealed interface VerifierResponse : DispatchOutcome {
        /**
         * When verifier/RP acknowledged the direct post
         */
        data class Accepted(val redirectURI: URI?) : VerifierResponse

        /**
         * When verifier/RP reject the direct post
         */
        data object Rejected : VerifierResponse {
            private fun readResolve(): Any = Rejected
        }
    }
}

/**
 * This interface assembles an appropriate authorization response given a [request][ResolvedRequestObject]
 * and holder's [consensus][Consensus] and then dispatches it to the verifier
 */
interface Dispatcher {

    /**
     * Assembles an appropriate authorization response given a [request][request]
     * and holder's [consensus][Consensus] and then dispatches it to the verifier.
     *
     * If [ResolvedRequestObject.responseMode] is
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     * dispatching takes the form of a [redirect URI][DispatchOutcome.RedirectURI] having the response
     * encoded. Wallet should redirect to this URI
     *
     * If [ResolvedRequestObject.responseMode] is [ResponseMode.DirectPost] or [ResponseMode.DirectPostJwt]
     * then dispatching takes the form of an actual post. The returned [DispatchOutcome.VerifierResponse]
     * contains the verifier's reply after receiving the post.
     *
     * @param request The request to reply to
     * @param consensus Holder's consensus (positive or negative) to this request
     * @return the dispatch outcome as described above
     */
    suspend fun dispatch(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome =
        when (request.responseMode) {
            is ResponseMode.DirectPost -> post(request, consensus, null)
            is ResponseMode.DirectPostJwt -> post(request, consensus, encryptionParameters)
            is ResponseMode.Query -> encodeRedirectURI(request, consensus, null)
            is ResponseMode.QueryJwt -> encodeRedirectURI(request, consensus, encryptionParameters)
            is ResponseMode.Fragment -> encodeRedirectURI(request, consensus, null)
            is ResponseMode.FragmentJwt -> encodeRedirectURI(request, consensus, encryptionParameters)
        }

    /**
     * Method forms a suitable authorization response, based on the [request] and the provided [consensus], then
     * post it to the Verifier's end-point and returns his response.
     *
     * This method is applicable when the [request] contains a [ResolvedRequestObject.responseMode] which is either
     * [ResponseMode.DirectPost] or [ResponseMode.DirectPostJwt].
     *
     * @param request The request to reply to. It must contain a [ResolvedRequestObject.responseMode] which is either
     * [ResponseMode.DirectPost] or [ResponseMode.DirectPostJwt]
     * @param consensus Holder's consensus (positive or negative) to this request
     * @return the verifier's response after receiving the authorization response.
     */
    suspend fun post(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters? = null,
    ): DispatchOutcome.VerifierResponse

    /**
     * Method forms a suitable authorization response, based on the [request] and the provided [consensus], and then
     * encodes this response to a URI.
     * To this URI, the wallet (caller) must redirect its authorization response
     *
     * This method is applicable when [request] contains a [ResolvedRequestObject.responseMode] which is one of
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     *
     * @param request The request to reply to. It must contain a [ResolvedRequestObject.responseMode] which is one of
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     * @param consensus Holder's consensus (positive or negative) to this request
     * @return a URI pointing to the verifier to which the wallet(caller) must redirect its response. This URI carries
     * the authorization response
     */
    suspend fun encodeRedirectURI(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters? = null,
    ): DispatchOutcome.RedirectURI
}
