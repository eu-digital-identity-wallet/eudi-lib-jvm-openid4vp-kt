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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix.*
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import eu.europa.ec.eudi.openid4vp.dcql.DCQL as DCQLQuery

/**
 * Examples assume that you have cloned and running
 * https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt
 */
fun main(): Unit = runBlocking {
    createHttpClient(enableLogging = true).use { httpClient ->
        httpClient.program()
    }
}

suspend fun HttpClient.program() {
    val verifierApi = URL("https://dev.verifier-backend.eudiw.dev")
    val wallet = Wallet(
        walletConfig = walletConfig(
            Preregistered(Verifier.asPreregisteredClient(verifierApi)),
            X509SanDns(TrustAnyX509),
            X509Hash(TrustAnyX509),
        ),
        httpClient = this@program,
    )

    suspend fun runUseCase(transaction: Transaction) = coroutineScope {
        println("Running ${transaction.name} ...")
        val verifier = Verifier.make(
            verifierApi = verifierApi,
            transaction = transaction,
        )

        when (val dispatchOutcome = wallet.handle(verifier.authorizationRequestUri)) {
            is DispatchOutcome.RedirectURI -> error("Unexpected")
            is DispatchOutcome.VerifierResponse.Accepted -> verifier.getWalletResponse(dispatchOutcome)
            DispatchOutcome.VerifierResponse.Rejected -> error("Unexpected failure")
        }
    }

    runUseCase(Transaction.MsoMdocPidDcql)
    runUseCase(Transaction.SdJwtVcPidDcql)
}

@Serializable
data class WalletResponse(
    @SerialName("vp_token") val vpToken: JsonObject? = null,
    @SerialName("error") val error: String? = null,
)

/**
 * This class is a minimal Verifier / RP application
 */
class Verifier private constructor(
    private val verifierApi: URL,
    private val presentationId: String,
    val authorizationRequestUri: URI,
) {

    override fun toString(): String =
        "Verifier presentationId=$presentationId, authorizationRequestUri=$authorizationRequestUri"

    suspend fun getWalletResponse(dispatchOutcome: DispatchOutcome.VerifierResponse.Accepted): WalletResponse {
        val responseCode = Url(checkNotNull(dispatchOutcome.redirectURI)).parameters["response_code"]
        checkNotNull(responseCode) { "Failed to extract response_code" }

        val walletResponse = createHttpClient().use {
            it.get("$verifierApi/ui/presentations/$presentationId?response_code=$responseCode") {
                accept(ContentType.Application.Json)
            }
        }.body<WalletResponse>()

        walletResponse.vpToken?.also { verifierPrintln("Got vp_token with payload $it") }
        return walletResponse
    }

    companion object {

        fun asPreregisteredClient(verifierApi: URL): PreregisteredClient {
            return PreregisteredClient(
                "Verifier",
                "Verifier",
                JWSAlgorithm.RS256 to JwkSetSource.ByReference(URI("$verifierApi/wallet/public-keys.json")),
            )
        }

        /**
         * Creates a new verifier that knows (out of bound) the
         * wallet's public key
         */
        suspend fun make(verifierApi: URL, transaction: Transaction): Verifier =
            coroutineScope {
                verifierPrintln("Initializing Verifier ...")
                withContext(Dispatchers.IO + CoroutineName("wallet-initTransaction")) {
                    createHttpClient().use { client ->
                        val nonce = randomNonce()
                        val initTransactionResponse =
                            initOpenId4VpTransaction(client, verifierApi, nonce, transaction.query, transaction.transactionData)
                        val presentationId = initTransactionResponse["transaction_id"]!!.jsonPrimitive.content
                        val uri = formatAuthorizationRequest(initTransactionResponse)
                        Verifier(verifierApi, presentationId, uri).also {
                            verifierPrintln("Initialized $it")
                        }
                    }
                }
            }

        private suspend fun initOpenId4VpTransaction(
            client: HttpClient,
            verifierApi: URL,
            nonce: String,
            query: DCQLQuery,
            transactionData: List<TransactionData>?,
        ): JsonObject {
            verifierPrintln("Placing to verifier endpoint OpenId4Vp authorization request  ...")
            val request = buildJsonObject {
                put("nonce", nonce)
                put("dcql_query", jsonSupport.encodeToJsonElement(query))
                put("response_mode", "direct_post.jwt")
                put("jar_mode", "by_reference")
                put("wallet_response_redirect_uri_template", "https://foo?response_code={RESPONSE_CODE}")
                if (!transactionData.isNullOrEmpty()) {
                    putJsonArray("transaction_data") {
                        addAll(transactionData.map { it.json })
                    }
                }
                put("request_uri_method", "post")
            }
            return initTransaction(client, verifierApi, request)
        }

        private suspend inline fun <reified B> initTransaction(
            client: HttpClient,
            verifierApi: URL,
            body: B,
        ): JsonObject =
            client.post("$verifierApi/ui/presentations") {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(body)
            }.body<JsonObject>()

        private fun formatAuthorizationRequest(iniTransactionResponse: JsonObject): URI {
            fun String.encode() = URLEncoder.encode(this, "UTF-8")
            val clientId = iniTransactionResponse["client_id"]?.jsonPrimitive?.content?.encode()!!
            val requestUri = buildString {
                iniTransactionResponse["request_uri"]?.jsonPrimitive?.contentOrNull?.encode()?.let { append("request_uri=$it") }
                iniTransactionResponse["request_uri_method"]?.jsonPrimitive?.contentOrNull?.let {
                    if (isNotBlank()) {
                        append("&")
                        append("request_uri_method=$it")
                    }
                }
            }.takeIf { it.isNotBlank() }

            val request = iniTransactionResponse["request"]?.jsonPrimitive?.contentOrNull?.let { "request=$it" }
            require(request != null || requestUri != null)
            val requestPart = requestUri ?: request
            return URI("eudi-wallet://authorize?client_id=$clientId&$requestPart")
        }

        private fun randomNonce(): String = Nonce().value

        private fun verifierPrintln(s: String) = println("Verifier : $s")
    }
}

data class Transaction(
    val query: DCQLQuery,
    val transactionData: List<TransactionData>? = null,
) {
    init {
        transactionData?.let {
            require(it.isNotEmpty()) { "transactionData must not be empty if provided" }
        }
    }

    val name: String = "OpenId4Vp"

    companion object {
        val MsoMdocPidDcql: Transaction = Transaction(
            jsonSupport.decodeFromString<DCQLQuery>(loadResource("/example/mso_mdoc-pid-dcql-query.json")),
        )

        val SdJwtVcPidDcql: Transaction = run {
            val dcql = jsonSupport.decodeFromString<DCQLQuery>(loadResource("/example/sd-jwt-vc-pid-dcql-query.json"))
            val queryId = dcql.credentials.ids.first()
            val transactionData = TransactionData.sdJwtVc(
                TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                listOf(queryId),
            ) {
                put("purpose", "We must verify your Family Name")
            }

            Transaction(dcql, listOf(transactionData))
        }
    }
}

private class Wallet(
    private val walletConfig: OpenId4VPConfig,
    private val httpClient: HttpClient,
) {
    private val openId4Vp: OpenId4Vp by lazy {
        OpenId4Vp(walletConfig, httpClient)
    }

    suspend fun handle(uri: URI): DispatchOutcome {
        walletPrintln("Handling $uri ...")
        return withContext(Dispatchers.IO) {
            openId4Vp.handle(uri.toString()) { holderConsent(it) }.also {
                walletPrintln("Response was sent to verifierApi which replied with $it")
            }
        }
    }

    suspend fun OpenId4Vp.handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus,
    ): DispatchOutcome =
        when (val resolution = resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw resolution.error.asException()
            is Resolution.Success -> {
                val requestObject = resolution.requestObject
                val consensus = holderConsensus(requestObject)
                dispatch(requestObject, consensus, EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")))
            }
        }

    suspend fun holderConsent(request: ResolvedRequestObject): Consensus =
        withContext(Dispatchers.Default) {
            val query = request.query
            check(1 == query.credentials.value.size) { "found more than 1 credentials" }
            val credential = query.credentials.value.first()
            val verifiablePresentation = when (val format = credential.format.value) {
                "mso_mdoc" -> VerifiablePresentation.Generic(loadResource("/example/mso_mdoc_pid-deviceresponse.txt"))
                "dc+sd-jwt" -> prepareSdJwtVcVerifiablePresentation(request.client, request.nonce, request.transactionData)
                else -> error("unsupported format $format")
            }

            Consensus.PositiveConsensus(
                verifiablePresentations = VerifiablePresentations(
                    value = mapOf(
                        credential.id to listOf(verifiablePresentation),
                    ),
                ),
            )
        }

    private fun prepareSdJwtVcVerifiablePresentation(
        audience: Client,
        nonce: String,
        transactionData: List<TransactionData>?,
    ): VerifiablePresentation.Generic {
        val sdJwtVc = loadResource("/example/sd-jwt-vc-pid.txt")
        val holderKey = ECKey.parse(loadResource("/example/sd-jwt-vc-pid-key.json"))
        check(holderKey.isPrivate) { "a private key is required" }

        val sdHash = run {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(sdJwtVc.encodeToByteArray())
            base64UrlNoPadding.encode(digest.digest())
        }
        val keyBindingJwt = run {
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("kb+jwt"))
                .keyID(holderKey.keyID)
                .build()
            val claims = JWTClaimsSet.Builder()
                .audience(audience.id.clientId)
                .claim("nonce", nonce)
                .issueTime(Date.from(walletConfig.clock.instant()))
                .claim("sd_hash", sdHash)
                .apply {
                    if (!transactionData.isNullOrEmpty()) {
                        check(transactionData.all { it is TransactionData.SdJwtVc && HashAlgorithm.SHA_256 in it.hashAlgorithmsOrDefault })

                        val transactionDataHashes = transactionData.map {
                            val digest = MessageDigest.getInstance("SHA-256")
                            digest.update(it.value.encodeToByteArray())
                            base64UrlNoPadding.encode(digest.digest())
                        }

                        claim("transaction_data_hashes_alg", HashAlgorithm.SHA_256.name)
                        claim("transaction_data_hashes", transactionDataHashes)
                    }
                }
                .build()
            SignedJWT(header, claims).apply { sign(ECDSASigner(holderKey)) }
        }
        return VerifiablePresentation.Generic("$sdJwtVc${keyBindingJwt.serialize()}")
    }

    companion object {
        fun walletPrintln(s: String) = println("Wallet   : $s")
    }
}

private val TrustAnyX509: (List<X509Certificate>) -> Boolean = { _ ->
    println("Warning!! Trusting any certificate. Do not use in production")
    true
}

private fun walletConfig(vararg supportedClientIdPrefix: SupportedClientIdPrefix) =
    OpenId4VPConfig(
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
            supportedTransactionDataTypes = listOf(
                SupportedTransactionDataType.SdJwtVc(
                    TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                    setOf(HashAlgorithm.SHA_256),
                ),
            ),
        ),
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Both(
                SupportedRequestUriMethods.Post(
                    jarEncryption = EncryptionRequirement.Required(
                        supportedEncryptionAlgorithms = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_ALGORITHMS,
                        supportedEncryptionMethods = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_METHODS,
                        ephemeralEncryptionKeyCurve = Curve.P_521,
                    ),
                ),
            ),
        ),
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
            supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
            supportedMethods = listOf(EncryptionMethod.A128GCM),
        ),
        supportedClientIdPrefixes = supportedClientIdPrefix,
        clock = Clock.systemDefaultZone(),
    )

private object Resource

private fun loadResource(resource: String): String =
    Resource.javaClass.getResource(resource)
        ?.readText()
        ?: error("resource '$resource' not found")
