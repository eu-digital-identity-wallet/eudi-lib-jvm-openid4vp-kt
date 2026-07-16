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
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.AuthorizationPolicyValidationError.NonRecoverable.*
import eu.europa.ec.eudi.openid4vp.AuthorizationPolicyValidationError.Recoverable.AuthorizationPolicyNotMet
import eu.europa.ec.eudi.openid4vp.AuthorizationPolicyValidationError.Recoverable.UnexpectedAuthenticatedClientType
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
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

    suspend fun authorize(request: ResolvedRequestObject)

    companion object {
        operator fun invoke(
            policy: RegistrationCertificatePolicy,
        ): RequestAuthorizer = RequestAuthorizer { request ->

            val verifierInfo = request.verifierInfo
            ensureNotNull(verifierInfo) { MissingRequiredRegistrationCertificate.asException() }

            val wrprc = verifierInfo.registrationCertificate
            ensureNotNull(wrprc) { MissingRequiredRegistrationCertificate.asException() }

            val x5c = wrprc.trustedX509CertChain(policy.trust)
            wrprc.verifySignature(x5c)

            val authorizedClient = request.client
            ensure(authorizedClient is Client.X509Hash) { UnexpectedAuthenticatedClientType.asException() }

            val violations = policy.apply(authorizedClient.cert, wrprc, request.query)
            ensure(violations.isEmpty()) { AuthorizationPolicyNotMet(violations).asException() }
        }
    }
}

private fun SignedJWT.trustedX509CertChain(trust: X509CertificateTrust): List<X509Certificate> {
    val x5c = header?.x509CertChain
    ensureNotNull(x5c) { malformedRegistrationCertificate("Missing x5c") }
    val pubCertChain = x5c.mapNotNull { runCatchingCancellable { X509CertUtils.parse(it.decode()) }.getOrNull() }
    ensure(pubCertChain.isNotEmpty()) { malformedRegistrationCertificate("Invalid x5c") }
    ensure(trust.isTrusted(pubCertChain)) { RegistrationCertificateNotTrusted.asException() }
    return pubCertChain
}

private fun SignedJWT.verifySignature(x5c: List<X509Certificate>) {
    try {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
            jwsKeySelector = JWSKeySelector<SecurityContext> { _, _ -> listOf(x5c.first().publicKey) }
        }
        jwtProcessor.process(this, null)
    } catch (e: JOSEException) {
        throw RuntimeException(e)
    } catch (e: BadJOSEException) {
        throw malformedRegistrationCertificate("Registration certificate invalid signature ${e.message}")
    }
}

private fun malformedRegistrationCertificate(cause: String): AuthorizationRequestException =
    MalformedRegistrationCertificate(cause).asException()
