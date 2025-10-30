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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.*
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.assertDoesNotThrow
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthorizationResponseBuilderTest {

    internal object Wallet {

        val config = OpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
                supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
                supportedMethods = listOf(EncryptionMethod.A256GCM),
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
    }

    internal object Verifier {

        private val responseEncryptionKeyPair: ECKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        val metaDataRequestingNotEncryptedResponse = UnvalidatedClientMetaData(
            vpFormatsSupported = VpFormatsSupported(
                msoMdoc = VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )

        val metaDataRequestingEncryptedResponse = UnvalidatedClientMetaData(
            jwks = JWKSet(responseEncryptionKeyPair).toJsonObject(true),
            responseEncryptionMethodsSupported = listOf(EncryptionMethod.A256GCM.name),
            vpFormatsSupported = VpFormatsSupported(
                sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP,
                msoMdoc = VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        )

        private fun JWKSet.toJsonObject(publicKeysOnly: Boolean = true): JsonObject =
            Json.parseToJsonElement(this.toString(publicKeysOnly)).jsonObject
    }

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `when direct_post jwt, builder should return DirectPostJwt with response encryption parameters of correct type`() = runTest {
        fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val query = DCQL(
                credentials = Credentials(
                    CredentialQuery.sdJwtVc(
                        id = QueryId("query_for_identity"),
                        DCQLMetaSdJwtVcExtensions(
                            vctValues = listOf("identity_credential"),
                        ),
                    ),
                ),
            )
            val verifierMetaData = assertDoesNotThrow {
                ClientMetaDataValidator.validateClientMetaData(
                    Verifier.metaDataRequestingEncryptedResponse,
                    responseMode,
                    query,
                    Wallet.config.responseEncryptionConfiguration,
                    Wallet.config.vpConfiguration.vpFormatsSupported,
                )
            }
            val resolvedRequest =
                ResolvedRequestObject(
                    query = query,
                    responseEncryptionSpecification = verifierMetaData.responseEncryptionSpecification,
                    vpFormatsSupported = VpFormatsSupported(
                        msoMdoc = VpFormatsSupported.MsoMdoc(
                            issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                            deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        ),
                    ),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    transactionData = null,
                    verifierInfo = null,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus(
                VerifiablePresentations(
                    mapOf(
                        QueryId("pdId") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                    ),
                ),
            )
            val response = resolvedRequest.responseWith(vpTokenConsensus, null)

            assertTrue("Response not of the expected type DirectPostJwt") { response is AuthorizationResponse.DirectPostJwt }
            assertIs<AuthorizationResponse.DirectPostJwt>(response)
            val responseEncryptionSpecification = response.responseEncryptionSpecification
            assertNotNull(responseEncryptionSpecification)
        }

        test(genState())
        test()
    }
}
