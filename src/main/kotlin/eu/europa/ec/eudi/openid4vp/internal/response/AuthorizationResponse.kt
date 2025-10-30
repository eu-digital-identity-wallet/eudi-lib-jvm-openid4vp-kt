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
package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.*
import java.net.URI
import java.net.URL

/**
 * The payload of an [AuthorizationResponse]
 */
internal sealed interface AuthorizationResponsePayload : java.io.Serializable {

    val nonce: String?
    val state: String?
    val clientId: VerifierId?
    val encryptionParameters: EncryptionParameters?

    /**
     * In response to a [ResolvedRequestObject].
     *
     * @property verifiablePresentations the vp related information that fulfils the [ResolvedRequestObject.query]
     * @property state the state of the [request][ResolvedRequestObject.state]
     * @property encryptionParameters the encryption parameters that may be needed during the response dispatch
     */
    data class Success(
        val verifiablePresentations: VerifiablePresentations,
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : AuthorizationResponsePayload

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.NegativeConsensus]
     * @param state the state of the [request][ResolvedRequestObject.state]
     */
    data class NoConsensusResponseData(
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Failed

    /**
     * In response of an [Resolution.Invalid] authorization request
     * @param error the cause
     * @param state the state of the request
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val nonce: String?,
        override val state: String?,
        override val clientId: VerifierId?,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Failed
}

/**
 * An OAUTH2 authorization response
 */
internal sealed interface AuthorizationResponse : java.io.Serializable {

    /**
     * An authorization response to be communicated to verifier/RP via direct_post method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization response
     */
    data class DirectPost(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via direct_post.jwt method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization response
     * @param responseEncryptionSpecification the verifier/RP's requirements for authorization response encryption
     */
    data class DirectPostJwt(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
        val responseEncryptionSpecification: ResponseEncryptionSpecification?,
    ) : AuthorizationResponse {
        init {
            if (data !is AuthorizationResponsePayload.InvalidRequest) {
                requireNotNull(responseEncryptionSpecification)
            }
        }
    }

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * query parameters
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     */
    data class Query(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * query parameters and authorization response encryption
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     * @param responseEncryptionSpecification the verifier/RP's requirements for authorization response encryption
     */
    data class QueryJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val responseEncryptionSpecification: ResponseEncryptionSpecification?,
    ) : AuthorizationResponse {
        init {
            if (data !is AuthorizationResponsePayload.InvalidRequest) {
                requireNotNull(responseEncryptionSpecification)
            }
        }
    }

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * fragment
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     */
    data class Fragment(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * fragment and authorization response encryption
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     * @param responseEncryptionSpecification the verifier/RP's requirements for authorization response encryption
     */
    data class FragmentJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val responseEncryptionSpecification: ResponseEncryptionSpecification?,
    ) : AuthorizationResponse {
        init {
            if (data !is AuthorizationResponsePayload.InvalidRequest) {
                requireNotNull(responseEncryptionSpecification)
            }
        }
    }
}

internal fun ResolvedRequestObject.responseWith(
    consensus: Consensus,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponse {
    val payload = responsePayload(consensus, encryptionParameters)
    return responseWith(payload)
}

private fun ResolvedRequestObject.responsePayload(
    consensus: Consensus,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponsePayload = when (consensus) {
    is Consensus.NegativeConsensus ->
        AuthorizationResponsePayload.NoConsensusResponseData(
            nonce,
            state,
            client.id,
            encryptionParameters,
        )

    is Consensus.PositiveConsensus -> {
        AuthorizationResponsePayload.Success(
            consensus.verifiablePresentations,
            nonce,
            state,
            client.id,
            encryptionParameters,
        )
    }
}

private fun ResolvedRequestObject.responseWith(
    data: AuthorizationResponsePayload,
): AuthorizationResponse =
    when (val mode = responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(mode.responseURI, data)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(
            mode.responseURI,
            data,
            checkNotNull(responseEncryptionSpecification),
        )
        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(mode.redirectUri, data)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(
            mode.redirectUri,
            data,
            checkNotNull(responseEncryptionSpecification),
        )
        is ResponseMode.Query -> AuthorizationResponse.Query(mode.redirectUri, data)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(mode.redirectUri, data, checkNotNull(responseEncryptionSpecification))
    }
