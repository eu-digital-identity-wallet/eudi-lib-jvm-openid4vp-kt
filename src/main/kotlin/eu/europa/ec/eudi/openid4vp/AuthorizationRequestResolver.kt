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

import eu.europa.ec.eudi.openid4vp.Client.*
import eu.europa.ec.eudi.openid4vp.TransactionData.Companion.credentialIds
import eu.europa.ec.eudi.openid4vp.TransactionData.Companion.type
import eu.europa.ec.eudi.openid4vp.TransactionData.SdJwtVc.Companion.hashAlgorithms
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQueryIds
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.openid4vp.internal.*
import eu.europa.ec.eudi.openid4vp.internal.request.RequestUriMethod
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.net.URI
import java.security.cert.X509Certificate

/**
 * Represents an OAuth2 RP that submitted an Authorization Request.
 */
sealed interface Client : java.io.Serializable {

    data class Preregistered(val clientId: OriginalClientId, val legalName: String) : Client
    data class RedirectUri(val clientId: URI) : Client
    data class DecentralizedIdentifier(val clientId: URI) : Client
    data class VerifierAttestation(val clientId: OriginalClientId) : Client
    data class X509SanDns(val clientId: OriginalClientId, val cert: X509Certificate) : Client
    data class X509Hash(val clientId: OriginalClientId, val cert: X509Certificate) : Client

    /**
     * The id of the client prefixed with the client id prefix.
     */
    val id: VerifierId
        get() = when (this) {
            is Preregistered -> VerifierId(ClientIdPrefix.PreRegistered, clientId)
            is RedirectUri -> VerifierId(ClientIdPrefix.RedirectUri, clientId.toString())
            is DecentralizedIdentifier -> VerifierId(ClientIdPrefix.DecentralizedIdentifier, clientId.toString())
            is VerifierAttestation -> VerifierId(ClientIdPrefix.VerifierAttestation, clientId)
            is X509SanDns -> VerifierId(ClientIdPrefix.X509SanDns, clientId)
            is X509Hash -> VerifierId(ClientIdPrefix.X509Hash, clientId)
        }
}

/**
 * Gets the legal name (i.e., CN) from this [X509Certificate].
 */
fun X509Certificate.legalName(): String? {
    val distinguishedName = X500Name(subjectX500Principal.name)
    val commonNames = distinguishedName.getRDNs(BCStyle.CN).orEmpty().toList()
        .flatMap { it.typesAndValues.orEmpty().toList() }
        .map { it.value.toString() }
    return commonNames.firstOrNull { it.isNotBlank() }
}

/**
 * Gets the legal name of this [Client].
 *
 * @param legalName a function to extract a legal name from a [X509Certificate]. Defaults to [X509Certificate.legalName].
 */
fun Client.legalName(legalName: X509Certificate.() -> String? = X509Certificate::legalName): String? {
    return when (this) {
        is Preregistered -> this.legalName
        is RedirectUri -> null
        is DecentralizedIdentifier -> null
        is VerifierAttestation -> null
        is X509SanDns -> cert.legalName()
        is X509Hash -> cert.legalName()
    }
}

typealias Base64UrlSafe = String

/**
 * Represents resolved (i.e., supported by the Wallet) Transaction Data.
 *
 * @property value the Base64 Url-Safe encoded value of this Transaction Data
 * @property json this Transaction Data as a generic JsonObject
 * @property type the type of the Transaction Data
 * @property credentialIds identifiers of the requested Credentials this Transaction Data is applicable to
 */
sealed interface TransactionData : java.io.Serializable {
    val value: Base64UrlSafe
    val json: JsonObject
    val type: TransactionDataType
    val credentialIds: List<QueryId>

    companion object {
        private fun decode(value: Base64UrlSafe): JsonObject {
            val decoded = base64UrlNoPadding.decodeToByteString(value)
            return jsonSupport.decodeFromString(decoded.decodeToString())
        }

        private fun JsonObject.type(): TransactionDataType =
            requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE).let(::TransactionDataType)

        private fun JsonObject.credentialIds(): List<QueryId> =
            requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS).map(::QueryId)

        private fun JsonObject.typeAndCredentialIds(): Pair<TransactionDataType, List<QueryId>> = type() to credentialIds()

        fun parse(value: Base64UrlSafe, query: DCQL): Result<TransactionData> = runCatchingCancellable {
            val json = decode(value)

            // verify required properties are present
            val (_, credentialIds) = json.typeAndCredentialIds()

            val requestedCredentialIds = query.credentials.ids.toSet()
            require(requestedCredentialIds.containsAll(credentialIds)) {
                "Invalid Transaction Data '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}': '$credentialIds'"
            }

            val credentialFormats = query.credentials.value.filter { it.id in credentialIds }.map { it.format }.toSet()
            require(1 == credentialFormats.size) {
                "Transaction Data must refer to Credentials that use the same Format"
            }

            val format = credentialFormats.first()
            when (format) {
                Format.SdJwtVc -> SdJwtVc(value)
                else -> throw IllegalArgumentException("Unsupported Transaction Data Format '$format'")
            }
        }

        fun sdJwtVc(
            type: TransactionDataType,
            credentialIds: List<QueryId>,
            hashAlgorithms: List<HashAlgorithm>? = null,
            builder: JsonObjectBuilder.() -> Unit = {},
        ): SdJwtVc = SdJwtVc(type, credentialIds, hashAlgorithms, builder)
    }

    /**
     * Represents resolved (i.e., supported by the Wallet) SD-JWT VC Transaction Data.
     *
     * @property hashAlgorithms Hash Algorithms with which the Hash of this Transaction Data can be calculated
     */
    data class SdJwtVc internal constructor(override val value: Base64UrlSafe) : TransactionData {
        override val json: JsonObject by lazy { decode(value) }
        override val type: TransactionDataType get() = json.type()
        override val credentialIds: List<QueryId> get() = json.credentialIds()
        val hashAlgorithms: List<HashAlgorithm>? get() = json.hashAlgorithms()
        val hashAlgorithmsOrDefault: List<HashAlgorithm> get() = hashAlgorithms ?: listOf(DefaultHashAlgorithm)

        init {
            require(credentialIds.isNotEmpty()) {
                "Transaction Data '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}' must not be empty'"
            }

            hashAlgorithms?.let {
                require(it.isNotEmpty()) { "Transaction Data '${OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS}' must not be empty" }
            }
        }

        companion object {
            private val DefaultHashAlgorithm: HashAlgorithm get() = HashAlgorithm.SHA_256

            private fun JsonObject.hashAlgorithms(): List<HashAlgorithm>? =
                optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)?.map(::HashAlgorithm)

            operator fun invoke(
                type: TransactionDataType,
                credentialIds: List<QueryId>,
                hashAlgorithms: List<HashAlgorithm>? = null,
                builder: JsonObjectBuilder.() -> Unit = {},
            ): SdJwtVc {
                val json = buildJsonObject {
                    builder()

                    put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, type.value)
                    putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS) {
                        credentialIds.forEach { add(it.value) }
                    }
                    if (!hashAlgorithms.isNullOrEmpty()) {
                        putJsonArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS) {
                            hashAlgorithms.forEach { add(it.name) }
                        }
                    }
                }

                val serialized = jsonSupport.encodeToString(json)
                val base64 = base64UrlNoPadding.encode(serialized.encodeToByteArray())

                return SdJwtVc(base64)
            }
        }
    }
}

@JvmInline
value class VerifierInfo(val attestations: List<Attestation>) : java.io.Serializable {
    init {
        require(attestations.isNotEmpty())
    }
    override fun toString(): String = attestations.toString()

    @Serializable
    data class Attestation(
        @SerialName(OpenId4VPSpec.VERIFIER_INFO_FORMAT) @Required val format: Format,
        @SerialName(OpenId4VPSpec.VERIFIER_INFO_DATA) @Required val data: Data,
        @SerialName(OpenId4VPSpec.VERIFIER_INFO_CREDENTIAL_IDS) val credentialIds: CredentialQueryIds? = null,
    ) : java.io.Serializable {

        @Serializable
        @JvmInline
        value class Format(val value: String) : java.io.Serializable {
            init {
                require(value.isNotEmpty())
            }
            override fun toString(): String = value

            companion object {
                val Jwt: Format get() = Format(OpenId4VPSpec.VERIFIER_INFO_FORMAT_JWT)
            }
        }

        @Serializable
        @JvmInline
        value class Data(val value: JsonElement) : java.io.Serializable {
            init {
                require((value is JsonPrimitive && value.isString) || (value is JsonObject))
            }
            override fun toString(): String = value.toString()
        }
    }

    companion object {
        fun fromJson(json: JsonArray): Result<VerifierInfo> =
            runCatchingCancellable {
                VerifierInfo(jsonSupport.decodeFromJsonElement(json))
            }
    }
}

/**
 * Represents an OAuth 2.0 authorization request for presenting a **vp_token**.
 *
 * @property responseEncryptionSpecification The verifier's requirements, if any, for encrypting the authorization response
 * @property vpFormatsSupported Populated when client metadata are provided along with the request. It contains the formats
 *   that both wallet and requester support. It is calculated by comparing wallet's configuration
 *   (@see [OpenId4VPConfig].vpConfiguration)and the formats passed in request's client metadata.
 */
data class ResolvedRequestObject(
    val client: Client,
    val responseMode: ResponseMode,
    val state: String?,
    val nonce: String,
    val responseEncryptionSpecification: ResponseEncryptionSpecification?,
    val vpFormatsSupported: VpFormatsSupported?,
    val query: DCQL,
    val transactionData: List<TransactionData>?,
    val verifierInfo: VerifierInfo?,
) : java.io.Serializable

/**
 * Errors that can occur while validating and resolving an authorization request
 */
sealed interface AuthorizationRequestError : java.io.Serializable

data class HttpError(val cause: Throwable) : AuthorizationRequestError

/**
 * Validation errors that can occur while validating an authorization request
 */
sealed interface RequestValidationError : AuthorizationRequestError {

    data class InvalidJarJwt(val cause: String) : AuthorizationRequestError

    data object InvalidUseOfBothRequestAndRequestUri : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = InvalidUseOfBothRequestAndRequestUri
    }

    data class UnsupportedRequestUriMethod(val method: RequestUriMethod) : RequestValidationError
    data object InvalidRequestUriMethod : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = InvalidRequestUriMethod
    }

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : RequestValidationError

    data object MissingResponseType : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingResponseType
    }

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    //
    // Query source errors
    //
    data object MissingQuerySource : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingQuerySource
    }

    data object MultipleQuerySources : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MultipleQuerySources
    }

    data object InvalidClientId : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = InvalidClientId
    }

    data class InvalidDigitalCredentialsQuery(val cause: Throwable) : RequestValidationError

    data object UnsupportedQueryFormats : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = UnsupportedQueryFormats
    }

    data object InvalidRedirectUri : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = InvalidRedirectUri
    }

    data object MissingRedirectUri : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingRedirectUri
    }

    data object MissingResponseUri : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingResponseUri
    }

    data object InvalidResponseUri : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = InvalidResponseUri
    }

    data object ResponseUriMustNotBeProvided : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = ResponseUriMustNotBeProvided
    }

    data object RedirectUriMustNotBeProvided : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = RedirectUriMustNotBeProvided
    }

    data object MissingNonce : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingNonce
    }

    data object MissingScope : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingScope
    }

    data object MissingClientId : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingClientId
    }

    data object UnsupportedClientIdPrefix : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = UnsupportedClientIdPrefix
    }

    data class UnsupportedClientMetaData(val value: String) : RequestValidationError

    data class InvalidClientMetaData(val cause: String) : RequestValidationError

    data object MissingClientMetadataJwks : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = MissingClientMetadataJwks
    }

    data object IdTokenSigningAlgMissing : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = IdTokenSigningAlgMissing
    }

    data object IdTokenEncryptionAlgMissing : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = IdTokenEncryptionAlgMissing
    }

    data object IdTokenEncryptionMethodMissing : RequestValidationError {
        @Suppress("unused")
        private fun readResolve(): Any = IdTokenEncryptionMethodMissing
    }

    data class InvalidClientIdPrefix(val value: String) : RequestValidationError

    data class InvalidIdTokenType(val value: String) : RequestValidationError

    data class DIDResolutionFailed(val didUrl: String) : RequestValidationError

    data class InvalidVerifierInfo(val reason: String) : RequestValidationError
}

/**
 * Errors that can occur while resolving an authorization request
 */
sealed interface ResolutionError : AuthorizationRequestError {
    data class UnknownScope(val scope: Scope) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwksUnparsable(val cause: Throwable) : ResolutionError
    data class InvalidTransactionData(val cause: Throwable) : ResolutionError
    data object ClientVpFormatsNotSupportedFromWallet : ResolutionError {
        @Suppress("unused")
        private fun readResolve(): Any = ClientVpFormatsNotSupportedFromWallet
    }
}

/**
 * An exception indicating an expected [error] while validating and/or resolving
 * an authorization request
 */
data class AuthorizationRequestException(val error: AuthorizationRequestError) : RuntimeException()

/**
 * Convenient method that lifts an [AuthorizationRequestError] into
 * a [AuthorizationRequestException]
 */
fun AuthorizationRequestError.asException(): AuthorizationRequestException =
    AuthorizationRequestException(this)

/**
 * Convenient method that lifts an [AuthorizationRequestError] into
 * [Result] context (wrapping an [AuthorizationRequestException])
 */
fun <T> AuthorizationRequestError.asFailure(): Result<T> =
    Result.failure(asException())

/**
 * The outcome of [validating and resolving][AuthorizationRequestResolver.resolveRequestUri]
 * an authorization request.
 */
sealed interface Resolution {
    /**
     * Represents the success of validating and resolving an authorization request
     * into a [requestObject]
     */
    data class Success(val requestObject: ResolvedRequestObject) : Resolution

    /**
     * Represents the failure of validating or resolving an authorization request
     * due to [error]
     */
    data class Invalid(
        val error: AuthorizationRequestError,
        val dispatchDetails: ErrorDispatchDetails?,
    ) : Resolution {

        companion object {
            fun nonDispatchable(error: AuthorizationRequestError): Invalid = Invalid(error, null)
        }
    }
}

/**
 * Information required for an [AuthorizationRequestError] to be dispatchable.
 */
data class ErrorDispatchDetails(
    val responseMode: ResponseMode,
    val nonce: String?,
    val state: String?,
    val clientId: VerifierId?,
    val responseEncryptionSpecification: ResponseEncryptionSpecification?,
) : java.io.Serializable {
    companion object
}

/**
 * An interface that describes a service
 * that accepts an [authorization request]authorization request, validates it and resolves it (that is,
 * fetches parts of the authorization request which are provided by reference)
 *
 */
fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and request the provided [uri] into a [ResolvedRequestObject].
     */
    suspend fun resolveRequestUri(uri: String): Resolution
}
