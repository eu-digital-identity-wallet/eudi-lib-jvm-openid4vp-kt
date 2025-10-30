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

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestError
import eu.europa.ec.eudi.openid4vp.HttpError
import eu.europa.ec.eudi.openid4vp.RequestValidationError.*
import eu.europa.ec.eudi.openid4vp.ResolutionError.*

internal enum class AuthorizationRequestErrorCode(val code: String) {

    // OAuth2.0 & OpenID4VP

    /**
     * Requested scope value is invalid, unknown, or malformed
     */
    INVALID_SCOPE("invalid_scope"),

    /**
     * One of the following:
     *
     * The request contains more than one out of the following two options to communicate a requested Credential:
     * a dcql_query parameter, or a scope value representing a DQQL Query.
     *
     * The request uses the vp_token Response Type but does not request a Credential using any of the three options
     *
     * DCQL Query does not conform to the OpenId4VP specification.
     *
     * The Wallet does not support the Client Identifier Prefix passed in the Authorization Request
     *
     * The Client Identifier passed in the request did not belong to its Client Identifier prefix,
     * or requirements of a certain prefix was violated,
     * for example, an unsigned request was sent with Client Identifier prefix openid_federation
     */
    INVALID_REQUEST("invalid_request"),

    /**
     * The Wallet did not have the requested Credentials to satisfy the Authorization Request.
     * The End-User did not give consent to share the requested Credentials with the Verifier.
     * The Wallet failed to authenticate the End-User.
     */
    ACCESS_DENIED("access_denied"),

    /**
     * client_metadata parameter is present, but the Wallet recognizes Client Identifier and
     * knows metadata associated with it.
     *
     * Verifier's pre-registered metadata has been found based on the Client Identifier,
     * but client_metadata parameter is also present.
     */
    INVALID_CLIENT("invalid_client"),

    /**
     * The Wallet does not support any of the formats requested by the Verifier,
     * such as those included in the vp_formats registration parameter.
     */
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),

    /**
     * The value of the request_uri_method request parameter is neither get nor post (case-sensitive).
     */
    INVALID_REQUEST_URI_METHOD("invalid_request_uri_method"),
    INVALID_TRANSACTION_DATA("invalid_transaction_data"),

    // JAR errors
    /**
     * The request_uri in the authorization request returns an error or contains invalid data
     */
    INVALID_REQUEST_URI("invalid_request_uri"),

    /**
     * The request parameter contains an invalid Request Object
     */
    INVALID_REQUEST_OBJECT("invalid_request_object"),

    /**
     * The authorization server does not support the use of the request_uri parameter
     */
    REQUEST_URI_NOT_SUPPORTED("request_uri_not_supported"),

    PROCESSING_FAILURE("processing_error"),
    ;

    companion object {

        /**
         * Maps an [error] into a [AuthorizationRequestErrorCode]
         */
        fun fromError(error: AuthorizationRequestError): AuthorizationRequestErrorCode {
            return when (error) {
                is UnknownScope -> INVALID_SCOPE

                is InvalidClientIdPrefix,
                InvalidRedirectUri,
                InvalidResponseUri,
                MissingClientId,
                MissingNonce,
                MissingQuerySource,
                MultipleQuerySources,
                is InvalidDigitalCredentialsQuery,
                UnsupportedQueryFormats,
                MissingRedirectUri,
                MissingResponseType,
                MissingResponseUri,
                MissingScope,
                RedirectUriMustNotBeProvided,
                ResponseUriMustNotBeProvided,
                IdTokenSigningAlgMissing,
                IdTokenEncryptionAlgMissing,
                IdTokenEncryptionMethodMissing,
                is InvalidClientMetaData,
                is UnsupportedResponseMode,
                is UnsupportedResponseType,
                is UnsupportedClientMetaData,
                is InvalidIdTokenType,
                is HttpError,
                InvalidUseOfBothRequestAndRequestUri,
                is UnsupportedRequestUriMethod,
                is InvalidVerifierInfo,
                MissingClientMetadataJwks,
                is ClientMetadataJwksUnparsable,
                -> INVALID_REQUEST

                InvalidClientId, UnsupportedClientIdPrefix -> INVALID_CLIENT

                is InvalidRequestUriMethod -> INVALID_REQUEST_URI_METHOD

                is UnableToFetchRequestObject -> INVALID_REQUEST_URI
                is InvalidJarJwt -> INVALID_REQUEST_OBJECT

                is DIDResolutionFailed,
                -> PROCESSING_FAILURE

                is InvalidTransactionData -> INVALID_TRANSACTION_DATA

                ClientVpFormatsNotSupportedFromWallet -> VP_FORMATS_NOT_SUPPORTED
            }
        }
    }
}
