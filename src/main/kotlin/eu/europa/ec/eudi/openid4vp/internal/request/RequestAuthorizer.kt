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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.AuthorizationPolicyValidationError.*
import eu.europa.ec.eudi.openid4vp.VerifierInfo.Attestation
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.security.cert.X509Certificate

/**
 * Functional interface for authorizing a given request object based on a specified policy.
 * The primary purpose of this interface is to facilitate authorization by evaluating the
 * properties of the passed `ResolvedRequestObject` against the provided `RegistrationCertificatePolicy`.
 *
 * The implementation ensures that:
 * - A verifier's registration certificate is present and valid.
 * - The signature of the registration certificate is verified.
 * - The authenticated client in the request is of the expected type.
 * - The authorization policy does not have any violations.
 *
 * Methods:
 * - `authorize`: Executes the authorization logic for a given request.
 *
 * Companion Object:
 * - Provides a factory-style `invoke` operator function to create an instance
 *   of `RequestAuthorizer` with specific policy enforcement.
 */
internal fun interface RequestAuthorizer {

    suspend fun authorize(request: ResolvedRequestObject): List<PolicyViolation.Warning>

    companion object {

        operator fun invoke(
            policy: RegistrationCertificatePolicy,
        ): RequestAuthorizer = RequestAuthorizer { request ->

            val authenticatedClient = request.client
            ensure(authenticatedClient is Client.X509Hash) { AuthorizationPolicyApplicableOnlyForX509HashClient.asException() }

            val verifierInfo = request.verifierInfo
            ensureNotNull(verifierInfo) { MissingRequiredRegistrationCertificate.asException() }

            val wrprc = verifierInfo.registrationCertificate()

            val x5c = wrprc.trustedX509CertChain(policy.trust)
            wrprc.verifySignature(x5c)

            val violations = policy.apply(authenticatedClient.cert, wrprc, request.query)

            if (violations != null) {
                val errors = violations.filterIsInstance<PolicyViolation.Error>()
                ensure(errors.isEmpty()) { AuthorizationPolicyNotMet(errors).asException() }

                violations.filterIsInstance<PolicyViolation.Warning>()
            } else
                emptyList()
        }
    }
}

private fun VerifierInfo.registrationCertificate(): SignedJWT {
    val registrationCertificates = attestations.filter { it.format == Attestation.Format.REGISTRATION_CERTIFICATE }
    ensure(registrationCertificates.isNotEmpty()) { MissingRequiredRegistrationCertificate.asException() }
    ensure(registrationCertificates.size == 1) { MultipleRegistrationCertificates.asException() }
    val wrprcAttestation = registrationCertificates.first()
    ensure(wrprcAttestation.credentialIds == null) {
        malformedRegistrationCertificate("Provided credentialIds with registrations certificate while not expected")
    }
    val wrprc = try {
        val element = wrprcAttestation.data.value
        ensure(element is JsonPrimitive) {
            malformedRegistrationCertificate("Provided registration certificate is not a JSON primitive")
        }
        SignedJWT.parse(element.jsonPrimitive.content)
    } catch (e: Exception) {
        throw malformedRegistrationCertificate("Provided registration certificate is not a valid signed JWT: ${e.message}")
    }

    return wrprc
}

private suspend fun SignedJWT.trustedX509CertChain(trust: X509CertificateTrust): List<X509Certificate> {
    val x5c = header?.x509CertChain
    ensureNotNull(x5c) { malformedRegistrationCertificate("Missing x5c header") }
    val pubCertChain = x5c.mapNotNull { runCatchingCancellable { X509CertUtils.parse(it.decode()) }.getOrNull() }
    ensure(pubCertChain.isNotEmpty()) { malformedRegistrationCertificate("Invalid x5c") }
    ensure(trust.isTrusted(pubCertChain)) { RegistrationCertificateNotTrusted.asException() }

    val leafCert = pubCertChain.first()
    val jwk = JWK.parse(leafCert)
    ensure(jwk is AsymmetricJWK) {
        malformedRegistrationCertificate("WRPRC signing key must be asymmetric")
    }

    return pubCertChain
}

private fun SignedJWT.verifySignature(x5c: List<X509Certificate>) {
    try {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(ETSI119475.REG_CERT_HEADER_TYPE))
            jwsKeySelector = JWSKeySelector { _, _ -> listOf(x5c.first().publicKey) }
        }
        jwtProcessor.process(this, null)
    } catch (e: JOSEException) {
        throw malformedRegistrationCertificate("Could not verify signature of registration certificate: ${e.message}")
    } catch (e: BadJOSEException) {
        throw malformedRegistrationCertificate("Registration certificate invalid signature: ${e.message}")
    }
}

private fun malformedRegistrationCertificate(cause: String): AuthorizationRequestException =
    MalformedRegistrationCertificate(cause).asException()
