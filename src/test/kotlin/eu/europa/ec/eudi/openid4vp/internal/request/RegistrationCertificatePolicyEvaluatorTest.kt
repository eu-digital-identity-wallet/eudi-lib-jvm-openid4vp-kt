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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.InputStream
import java.security.cert.X509Certificate
import kotlin.test.*

class RegistrationCertificatePolicyEvaluatorTest {

    private val wrprcValid = load("certificates/wrprc.txt")!!.bufferedReader().readText()

    private val wrprcUnsigned = load("certificates/wrprc_unsigned.txt")!!.bufferedReader().readText()

    private val dummyCert: X509Certificate by lazy {
        val wrprc = SignedJWT.parse(wrprcValid)
        X509CertUtils.parse(wrprc.header.x509CertChain.first().decode())
    }

    private val dcql = DCQL(
        credentials = Credentials(
            listOf(
                CredentialQuery.sdJwtVc(
                    id = QueryId("q1"),
                    sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues = listOf("vct1")),
                ),
            ),
        ),
    )

    private val trustAll: (List<X509Certificate>) -> Boolean = { _ -> true }
    private val trustNone: (List<X509Certificate>) -> Boolean = { _ -> false }

    @Test
    fun `evaluate returns Granted when client is not X509Hash`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ ->
            RegistrationCertificatePolicy.Authorization.NotGranted(RegistrationCertificatePolicy.PolicyViolation("should not be called"))
        }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val request = resolvedRequestObject(client = Client.Origin("client-id"))

        val result = evaluator.evaluate(request)
        assertTrue(result is RegistrationCertificatePolicy.Authorization.Granted)
    }

    @Test
    fun `evaluate throws MissingRequiredRegistrationCertificate when client is X509Hash and verifierInfo is null`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = null)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        assertEquals(AuthorizationPolicyValidationError.MissingRequiredRegistrationCertificate, exception.error)
    }

    @Test
    fun `evaluate throws MissingRequiredRegistrationCertificate when client is X509Hash and WRPRC is missing`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.Jwt,
                    VerifierInfo.Attestation.Data(JsonPrimitive("dummy-jwt")),
                ),
            ),
        )
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = verifierInfo)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        assertEquals(AuthorizationPolicyValidationError.MissingRequiredRegistrationCertificate, exception.error)
    }

    @Test
    fun `evaluate throws RegistrationCertificateNotTrusted when registration certificate is not trusted`() = runTest {
        val policy = RegistrationCertificatePolicy(trustNone) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                ),
            ),
        )
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = verifierInfo)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        assertEquals(AuthorizationPolicyValidationError.RegistrationCertificateNotTrusted, exception.error)
    }

    @Test
    fun `evaluate throws MultipleRegistrationCertificates when more than one registration certificates are provided`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                ),
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                ),
            ),
        )
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = verifierInfo)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        assertEquals(AuthorizationPolicyValidationError.MultipleRegistrationCertificates, exception.error)
    }

    @Test
    fun `evaluate throws MalformedRegistrationCertificate when registration certificate is an unsigned jwt`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    VerifierInfo.Attestation.Data(JsonPrimitive(wrprcUnsigned)),
                ),
            ),
        )
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = verifierInfo)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        val error = exception.error
        assertIs<AuthorizationPolicyValidationError.MalformedRegistrationCertificate>(error)
        assertTrue(error.cause.contains("Provided registration certificate is not a valid signed JWT"))
    }

    @Test
    fun `evaluate throws MalformedRegistrationCertificate when WRPRC is passed as Attestation with credentialIds not null`() = runTest {
        val policy = RegistrationCertificatePolicy(trustAll) { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    format = VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    data = VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                    credentialIds = CredentialQueryIds(listOf(QueryId("q1"))),
                ),
            ),
        )
        val request = resolvedRequestObject(client = Client.X509Hash("client-id", dummyCert), verifierInfo = verifierInfo)

        val exception = assertFailsWith<AuthorizationRequestException> {
            evaluator.evaluate(request)
        }
        val error = exception.error
        assertIs<AuthorizationPolicyValidationError.MalformedRegistrationCertificate>(error)
        assertTrue(error.cause.contains("Provided credentialIds with registrations certificate while not expected"))
    }

    @Test
    fun `evaluate calls policy and returns its result when everything is valid`() = runTest {
        var policyCalled = false

        val policy = RegistrationCertificatePolicy(trustAll) { accessCert, registrationCert, dcqlParam ->
            policyCalled = true
            assertEquals(dummyCert, accessCert)
            assertNotNull(registrationCert)
            assertIs<JsonObject>(registrationCert)
            assertEquals(dcql, dcqlParam)
            RegistrationCertificatePolicy.Authorization.Granted()
        }
        val evaluator = RegistrationCertificatePolicyEvaluator(policy)
        val verifierInfo = VerifierInfo(
            listOf(
                VerifierInfo.Attestation(
                    VerifierInfo.Attestation.Format.REGISTRATION_CERTIFICATE,
                    VerifierInfo.Attestation.Data(JsonPrimitive(wrprcValid)),
                ),
            ),
        )
        val request = resolvedRequestObject(
            client = Client.X509Hash("client-id", dummyCert),
            verifierInfo = verifierInfo,
        )
        val result = evaluator.evaluate(request)

        assertTrue(result is RegistrationCertificatePolicy.Authorization.Granted)
        assertTrue(policyCalled)
    }

    private fun resolvedRequestObject(
        client: Client,
        verifierInfo: VerifierInfo? = null,
    ): ResolvedRequestObject = ResolvedRequestObject(
        client = client,
        responseMode = ResponseMode.DirectPost(java.net.URL("https://example.com")),
        state = "state",
        nonce = "nonce",
        responseEncryptionSpecification = null,
        vpFormatsSupported = null,
        query = dcql,
        transactionData = null,
        verifierInfo = verifierInfo,
    )

    private fun load(f: String): InputStream? =
        RegistrationCertificatePolicyEvaluatorTest::class.java.classLoader.getResourceAsStream(f)
}
