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
import eu.europa.ec.eudi.openid4vp.internal.response.AuthorizationResponse.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL

/**
 * Default implementation of [Dispatcher]
 */
internal class DefaultDispatcher(
    private val httpClient: HttpClient,
) : Dispatcher, ErrorDispatcher {

    override suspend fun post(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.VerifierResponse {
        val response = request.responseWith(consensus, encryptionParameters)
        return doPost(response)
    }

    override suspend fun post(
        error: AuthorizationRequestError,
        errorDispatchDetails: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.VerifierResponse {
        val response = error.responseWith(errorDispatchDetails, encryptionParameters)
        return doPost(response)
    }

    private suspend fun doPost(response: AuthorizationResponse): DispatchOutcome.VerifierResponse {
        val (responseUri, parameters) = formParameters(response)
        return submitForm(httpClient, responseUri, parameters)
    }

    private fun formParameters(
        response: AuthorizationResponse,
    ): Pair<URL, Parameters> =
        when (response) {
            is DirectPost -> {
                val parameters = parametersOf(null, response.data)
                response.responseUri to parameters
            }

            is DirectPostJwt -> {
                val parameters = parametersOf(response.responseEncryptionSpecification, response.data)
                response.responseUri to parameters
            }

            else -> error("Unexpected response $response")
        }

    /**
     * Submits an HTTP Form to [url] with the provided [parameters].
     */
    @OptIn(InternalAPI::class)
    private suspend fun submitForm(
        httpClient: HttpClient,
        url: URL,
        parameters: Parameters,
    ): DispatchOutcome.VerifierResponse {
        val response = httpClient.post(url.toExternalForm()) {
            body = FormData(parameters)
        }

        return when (response.status) {
            HttpStatusCode.OK -> {
                val redirectUri =
                    try {
                        response.body<JsonObject?>()
                            ?.get("redirect_uri")
                            ?.takeIf { it is JsonPrimitive }
                            ?.jsonPrimitive?.contentOrNull
                            ?.let { URI.create(it) }
                    } catch (_: NoTransformationFoundException) {
                        null
                    }
                DispatchOutcome.VerifierResponse.Accepted(redirectUri)
            }

            else -> DispatchOutcome.VerifierResponse.Rejected
        }
    }

    override suspend fun encodeRedirectURI(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.RedirectURI {
        val response = request.responseWith(consensus, encryptionParameters)
        return encodeRedirectURI(response)
    }

    override suspend fun encodeRedirectURI(
        error: AuthorizationRequestError,
        errorDispatchDetails: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.RedirectURI {
        val response = error.responseWith(errorDispatchDetails, encryptionParameters)
        return encodeRedirectURI(response)
    }

    private fun encodeRedirectURI(
        response: AuthorizationResponse,
    ): DispatchOutcome.RedirectURI {
        val uri = when (response) {
            is Fragment -> response.encodeRedirectURI()
            is FragmentJwt -> response.encodeRedirectURI()
            is Query -> response.encodeRedirectURI()
            is QueryJwt -> response.encodeRedirectURI()
            else -> error("Unexpected response $response")
        }

        return DispatchOutcome.RedirectURI(uri)
    }
}

internal fun parametersOf(
    responseEncryptionSpecification: ResponseEncryptionSpecification?,
    data: AuthorizationResponsePayload,
): Parameters =
    when {
        null != responseEncryptionSpecification -> {
            val encryptedJwt = responseEncryptionSpecification.encrypt(data)
            DirectPostJwtForm.parametersOf(encryptedJwt)
        }

        else -> DirectPostForm.parametersOf(data)
    }

internal fun Query.encodeRedirectURI(): URI =
    URLBuilder(redirectUri.toString())
        .apply {
            parameters.appendAll(parametersOf(null, data))
        }.build().toURI()

internal fun QueryJwt.encodeRedirectURI(): URI =
    URLBuilder(redirectUri.toString())
        .apply {
            parameters.appendAll(parametersOf(responseEncryptionSpecification, data))
        }.build().toURI()

internal fun Parameters.toFragment(): String =
    entries().flatMap { (key, values) -> values.map { value -> "$key=$value" } }.joinToString("&")

internal fun Fragment.encodeRedirectURI(): URI =
    URLBuilder(redirectUri.toString()).apply {
        fragment = parametersOf(null, data).toFragment()
    }.build().toURI()

internal fun FragmentJwt.encodeRedirectURI(): URI =
    URLBuilder(redirectUri.toString()).apply {
        fragment = parametersOf(responseEncryptionSpecification, data).toFragment()
    }.build().toURI()

/**
 * An object responsible for encoding a [AuthorizationResponsePayload] into
 * HTTP form
 */
internal object DirectPostForm {

    private const val VP_TOKEN_FORM_PARAM = "vp_token"
    private const val STATE_FORM_PARAM = "state"
    private const val ERROR_FORM_PARAM = "error"
    private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

    fun parametersOf(p: AuthorizationResponsePayload): Parameters =
        of(p).let { form ->
            parameters {
                form.entries.forEach { (name, value) -> append(name, value) }
            }
        }

    fun of(p: AuthorizationResponsePayload): Map<String, String> =
        when (p) {
            is AuthorizationResponsePayload.Success -> buildMap {
                put(VP_TOKEN_FORM_PARAM, p.verifiablePresentations.asParam())
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.InvalidRequest -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.fromError(p.error).code)
                put(ERROR_DESCRIPTION_FORM_PARAM, "${p.error}")
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.NoConsensusResponseData -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.ACCESS_DENIED.code)
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }
        }
}

internal fun VerifiablePresentations.asJsonObject(): JsonObject =
    buildJsonObject {
        value.entries
            .forEach { (queryId, verifiablePresentations) ->
                putJsonArray(queryId.value) {
                    verifiablePresentations.forEach { verifiablePresentation ->
                        when (verifiablePresentation) {
                            is VerifiablePresentation.Generic -> add(verifiablePresentation.value)
                            is VerifiablePresentation.JsonObj -> add(verifiablePresentation.value)
                        }
                    }
                }
            }
    }

internal fun VerifiablePresentations.asParam(): String = Json.encodeToString(asJsonObject())

internal object DirectPostJwtForm {
    fun parametersOf(encryptedJwt: Jwt): Parameters =
        Parameters.build {
            append("response", encryptedJwt)
        }
}

/**
 * [OutgoingContent] for `application/x-www-form-urlencoded` formatted requests that use US-ASCII encoding.
 */
internal class FormData(
    val formData: Parameters,
) : OutgoingContent.ByteArrayContent() {
    private val content = formData.formUrlEncode().toByteArray(Charsets.US_ASCII)

    override val contentLength: Long = content.size.toLong()
    override val contentType: ContentType = ContentType.Application.FormUrlEncoded

    override fun bytes(): ByteArray = content
}
