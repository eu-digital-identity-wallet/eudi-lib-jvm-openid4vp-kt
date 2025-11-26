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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig.Companion.SelfIssued
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration.NotSupported
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdPrefix.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param legalName the name of the trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is uses to sign his request and a [way][JwkSetSource] to get his public key
 *
 */
data class PreregisteredClient(
    val clientId: OriginalClientId,
    val legalName: String,
    val jarConfig: Pair<JWSAlgorithm, JwkSetSource>? = null,
)

fun interface X509CertificateTrust {
    fun isTrusted(chain: List<X509Certificate>): Boolean
}

fun interface LookupPublicKeyByDIDUrl {
    suspend fun resolveKey(didUrl: URI): PublicKey?
}

/**
 * The Client identifier prefix supported (or trusted) by the wallet.
 */
sealed interface SupportedClientIdPrefix {

    /**
     * The Client Identifier is known to the Wallet in advance of the Authorization Request.
     */
    data class Preregistered(val clients: Map<OriginalClientId, PreregisteredClient>) : SupportedClientIdPrefix {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    /**
     * Wallet trusts verifiers that present an authorization request having a redirect URI
     * equal to the value of the Client Identifier.
     *
     * In this prefix, Verifier must NOT sign his request
     */
    data object RedirectUri : SupportedClientIdPrefix

    /**
     * Wallet trusts verifiers that are able to present a client identifier which is a DID
     *
     * In this prefix, Verifier must always sign his request (JAR), signed by a key
     * that can be referenced via the DID
     *
     * @param lookup a function for getting the public key of the verifier by
     * resolving a given DID URL
     */
    data class DecentralizedIdentifier(val lookup: LookupPublicKeyByDIDUrl) : SupportedClientIdPrefix

    /**
     * Wallet trust verifiers that are able to present a signed Verifier Attestation, which
     * is issued by a party trusted by the Wallet
     *
     * In this prefix, Verifier must always sign his request (JAR), having in its JOSE
     * header a Verifier Attestation JWT under `jwt` claim
     *
     * @param trust a function for verifying the digital signature of the Verifier Attestation JWT.
     * @param clockSkew max acceptable skew between wallet and attestation issuer
     */
    data class VerifierAttestation(
        val trust: JWSVerifier,
        val clockSkew: Duration = Duration.ofSeconds(15L),
    ) : SupportedClientIdPrefix

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this prefix, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val trust: X509CertificateTrust) : SupportedClientIdPrefix {
        companion object {
            internal val NoValidation: X509SanDns = X509SanDns { _ -> true }
        }
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is the SHA256 hash of the DER encoded
     * leaf certificate passed with the request.
     *
     * In this prefix, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509Hash(val trust: X509CertificateTrust) : SupportedClientIdPrefix

    fun prefix(): ClientIdPrefix = when (this) {
        is Preregistered -> ClientIdPrefix.PreRegistered
        RedirectUri -> ClientIdPrefix.RedirectUri
        is DecentralizedIdentifier -> ClientIdPrefix.DecentralizedIdentifier
        is VerifierAttestation -> ClientIdPrefix.VerifierAttestation
        is X509SanDns -> ClientIdPrefix.X509SanDns
        is X509Hash -> ClientIdPrefix.X509Hash
    }
}

/**
 * A type of Transaction Data supported by the Wallet.
 */
sealed interface SupportedTransactionDataType {
    val type: TransactionDataType

    data class SdJwtVc(
        override val type: TransactionDataType,
        val hashAlgorithms: Set<HashAlgorithm>,
    ) : SupportedTransactionDataType {
        init {
            require(hashAlgorithms.isNotEmpty()) { "hashAlgorithms cannot be empty" }
            require(HashAlgorithm.SHA_256 in hashAlgorithms) { "'${HashAlgorithm.SHA_256.name}' must be a supported hash algorithm" }
        }
    }
}

/**
 * Configuration options for OpenId4VP
 *
 * @param knownDCQLQueriesPerScope a set of DCQL queries that a verifier may request via a pre-agreed scope
 * @param vpFormatsSupported The formats the wallet supports
 * @param supportedTransactionDataTypes the types of Transaction Data that are supported by the wallet
 */
data class VPConfiguration(
    val knownDCQLQueriesPerScope: Map<String, DCQL> = emptyMap(),
    val vpFormatsSupported: VpFormatsSupported,
    val supportedTransactionDataTypes: List<SupportedTransactionDataType> = emptyList(),
) {
    init {
        if (null == vpFormatsSupported.sdJwtVc) {
            require(supportedTransactionDataTypes.none { it is SupportedTransactionDataType.SdJwtVc }) {
                "SD-JWT VC Transaction Data cannot be used when SD-JWT VC is not supported"
            }
        }
    }
}

/**
 * Configurations options for encrypting an authorization response if requested by the verifier.
 *
 * OpenId4VP recommends supporting [encrypting][Supported] the authorization response
 */
sealed interface ResponseEncryptionConfiguration {

    /**
     * The wallet supports encrypting authorization responses
     *
     * @param supportedAlgorithms the JWE algorithms that the wallet can use
     * when encrypting the authorization response in order of preference
     * @param supportedMethods the JWE encryption methods that the wallet can use
     * when encrypting the authorization response in order of preference
     * [EncryptionMethod.XC20P] requires the usage of [com.google.crypto.tink:tink](https://central.sonatype.com/artifact/com.google.crypto.tink/tink)
     */
    data class Supported(
        val supportedAlgorithms: List<JWEAlgorithm>,
        val supportedMethods: List<EncryptionMethod>,
    ) : ResponseEncryptionConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least an encryption algorithm must be provided" }
            require(supportedMethods.isNotEmpty()) { "At least an encryption method must be provided" }
        }
    }

    /**
     * Wallet doesn't support replying using unencrypted authorization responses
     */
    data object NotSupported : ResponseEncryptionConfiguration
}

sealed interface NonceOption {
    data object DoNotUse : NonceOption

    @JvmInline
    value class Use(val byteLength: Int = 32) : NonceOption {
        init {
            require(byteLength > 1) { "Byte length should be greater than 1" }
        }
    }
}

/**
 * Wallet articulated encryption requirements.
 */
sealed interface EncryptionRequirement : java.io.Serializable {

    /**
     * Encryption is not required.
     */
    data object NotRequired : EncryptionRequirement {
        private fun readResolve(): Any = NotRequired
    }

    /**
     * Encryption is required.
     *
     * @property supportedEncryptionAlgorithms encryption algorithms supported by the Wallet, only asymmetric JWEAlgorithms are supported
     * @property supportedEncryptionMethods encryption methods supported by the Wallet, [EncryptionMethod.XC20P] requires the usage
     * of [com.google.crypto.tink:tink](https://central.sonatype.com/artifact/com.google.crypto.tink/tink)
     * @property ephemeralEncryptionKeyCurve the [Curve] to use for generating the ephemeral encryption key
     */
    data class Required(
        val supportedEncryptionAlgorithms: List<JWEAlgorithm>,
        val supportedEncryptionMethods: List<EncryptionMethod>,
        val ephemeralEncryptionKeyCurve: Curve,
    ) : EncryptionRequirement {
        init {
            require(supportedEncryptionAlgorithms.isNotEmpty()) { "supportedEncryptionAlgorithms cannot be empty" }
            require(SUPPORTED_ENCRYPTION_ALGORITHMS.containsAll(supportedEncryptionAlgorithms)) {
                "only the following JWEAlgorithms are supported: $SUPPORTED_ENCRYPTION_ALGORITHMS"
            }
            require(supportedEncryptionMethods.isNotEmpty()) { "supportedEncryptionMethods cannot be empty" }
            require(SUPPORTED_ENCRYPTION_METHODS.containsAll(supportedEncryptionMethods)) {
                "only the following EncryptionMethods are supported: $SUPPORTED_ENCRYPTION_METHODS"
            }
            require(ephemeralEncryptionKeyCurve in SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES) {
                "only the following Curves are supported: $SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES"
            }
        }

        companion object {
            val SUPPORTED_ENCRYPTION_ALGORITHMS: List<JWEAlgorithm> get() = ECDHDecrypter.SUPPORTED_ALGORITHMS.toList()
            val SUPPORTED_ENCRYPTION_METHODS: List<EncryptionMethod> get() = ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS.toList()
            val SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES: List<Curve> get() = ECDHDecrypter.SUPPORTED_ELLIPTIC_CURVES.toList()
        }
    }
}

/**
 * Which of the `request_uri_method` are supported by the wallet
 */
sealed interface SupportedRequestUriMethods {

    /**
     * Indicates support to `request_uri_method` `get`
     */
    data object Get : SupportedRequestUriMethods

    /**
     * Options related to `request_uri_method` equal to `post`
     *
     * @param includeWalletMetadata whether to include wallet metadata or not
     * @param jarEncryption whether to request JAR be encrypted or not
     * @param useWalletNonce whether to use wallet_nonce
     */
    data class Post(
        val includeWalletMetadata: Boolean = true,
        val jarEncryption: EncryptionRequirement = EncryptionRequirement.NotRequired,
        val useWalletNonce: NonceOption = NonceOption.Use(),
    ) : SupportedRequestUriMethods {
        init {
            require(EncryptionRequirement.NotRequired == jarEncryption || includeWalletMetadata) {
                "Wallet Metadata must be included when JAR encryption is required"
            }
        }
    }

    /**
     * Both methods are supported
     */
    data class Both(val post: Post) : SupportedRequestUriMethods

    fun isGetSupported(): Boolean = when (this) {
        is Both, Get -> true
        is Post -> false
    }

    fun isPostSupported(): Post? = when (this) {
        is Both -> post
        Get -> null
        is Post -> this
    }

    companion object {
        /**
         * The default option is to support both `get` and `post` and in the later case,
         * include `wallet_metadata` and `wallet_nonce`, and NOT require JAR be encrypted
         */
        val Default: SupportedRequestUriMethods = Both(post = Post())
    }
}

/**
 * Options related to JWT-Secured authorization requests
 *
 * @param supportedAlgorithms the algorithms supported for the signature of the JAR
 * @param supportedRequestUriMethods which of the `request_uri_method` methods are supported
 */
data class JarConfiguration(
    val supportedAlgorithms: List<JWSAlgorithm>,
    val supportedRequestUriMethods: SupportedRequestUriMethods = SupportedRequestUriMethods.Default,
) {
    init {
        require(supportedAlgorithms.isNotEmpty()) { "JAR signing algorithms cannot be empty" }
    }

    companion object {
        /**
         * The default JAR configuration list as trusted algorithms ES256, ES384, and ES512.
         * Also, both `request_uri_method` are supported.
         *
         * @see SupportedRequestUriMethods.Default
         */
        val Default = JarConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512),
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
        )
    }
}

/**
 * Wallets policy regarding error dispatching.
 */
enum class ErrorDispatchPolicy : java.io.Serializable {

    /**
     * Allow dispatching of errors to all clients, regardless of authentication status.
     */
    AllClients,

    /**
     * Allow dispatching of errors only to authenticated clients.
     */
    OnlyAuthenticatedClients,
}

/**
 * Wallet configuration options for OpenId4VP protocol.
 *
 * At minimum, a wallet configuration should define at least a [supportedClientIdPrefixes]
 *
 * @param issuer an id for the wallet, defaults to [SelfIssued].
 * @param jarConfiguration options related to JWT Secure authorization requests.
 * If not provided, it will default to [JarConfiguration.Default]
 * @param responseEncryptionConfiguration whether wallet supports authorization response encryption. If not specified, it takes the default value
 * [ResponseEncryptionConfiguration.NotSupported].
 * @param vpConfiguration options about OpenId4VP.
 * @param clock the system Clock. If not provided system's default clock will be used.
 * @param jarClockSkew max acceptable skew between wallet and verifier
 * @param supportedClientIdPrefixes the client id prefixes that are supported/trusted by the wallet
 * @param errorDispatchPolicy wallet's policy regarding error dispatching. Defaults to [ErrorDispatchPolicy.OnlyAuthenticatedClients].
 */
data class OpenId4VPConfig(
    val issuer: Issuer = SelfIssued,
    val jarConfiguration: JarConfiguration = JarConfiguration.Default,
    val responseEncryptionConfiguration: ResponseEncryptionConfiguration = NotSupported,
    val vpConfiguration: VPConfiguration,
    val clock: Clock = Clock.systemDefaultZone(),
    val jarClockSkew: Duration = Duration.ofSeconds(15L),
    val supportedClientIdPrefixes: List<SupportedClientIdPrefix>,
    val errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
) {
    init {
        require(supportedClientIdPrefixes.isNotEmpty()) { "At least a supported client id prefix must be provided" }
    }

    constructor(
        issuer: Issuer = SelfIssued,
        jarConfiguration: JarConfiguration = JarConfiguration.Default,
        responseEncryptionConfiguration: ResponseEncryptionConfiguration = NotSupported,
        vpConfiguration: VPConfiguration,
        clock: Clock = Clock.systemDefaultZone(),
        jarClockSkew: Duration = Duration.ofSeconds(15L),
        errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
        vararg supportedClientIdPrefixes: SupportedClientIdPrefix,
    ) : this(
        issuer,
        jarConfiguration,
        responseEncryptionConfiguration,
        vpConfiguration,
        clock,
        jarClockSkew,
        supportedClientIdPrefixes.toList(),
        errorDispatchPolicy,
    )

    companion object {
        /**
         * Identifies the wallet as `https://self-issued.me/v2`
         */
        val SelfIssued = Issuer(URI.create("https://self-issued.me/v2"))
    }
}

internal fun OpenId4VPConfig.supportedClientIdPrefix(prefix: ClientIdPrefix): SupportedClientIdPrefix? =
    supportedClientIdPrefixes.firstOrNull { it.prefix() == prefix }

@Deprecated("Use OpenId4VPConfig instead", ReplaceWith("OpenId4VPConfig"))
typealias SiopOpenId4VPConfig = OpenId4VPConfig
