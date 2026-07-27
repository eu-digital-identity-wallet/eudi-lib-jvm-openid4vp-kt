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

import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.AuthorizationPolicyValidationError.*
import eu.europa.ec.eudi.openid4vp.VerifierInfo.Attestation
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/**
 * Functional interface that evaluates a registration certificate policy in the context of an incoming
 * authorization request. This interface is meant to evaluate whether an authenticated client meets the
 * requirements defined by a specific policy for WRP registration certificates.
 *
 * The decision returned by the evaluation is an instance of `RegistrationCertificatePolicy.Authorization`,
 * which can either grant or deny authorization depending on whether the client complies with the policy.
 */
internal fun interface RegistrationCertificatePolicyEvaluator {

    suspend fun evaluate(request: ResolvedRequestObject): RegistrationCertificatePolicy.Authorization

    companion object {

        operator fun invoke(
            policy: RegistrationCertificatePolicy,
        ): RegistrationCertificatePolicyEvaluator = RegistrationCertificatePolicyEvaluator { request ->

            val authenticatedClient = request.client
            if (authenticatedClient !is Client.X509Hash) {
                RegistrationCertificatePolicy.Authorization.Granted()
            } else {
                val verifierInfo = request.verifierInfo
                ensureNotNull(verifierInfo) { MissingRequiredRegistrationCertificate.asException() }
                val wrprc = verifierInfo.registrationCertificate()

                policy.invoke(
                    authenticatedClient.cert,
                    wrprc,
                    request.query,
                )
            }
        }
    }
}

private fun VerifierInfo.registrationCertificate(): String {
    val registrationCertificates = attestations.filter { it.format == Attestation.Format.REGISTRATION_CERTIFICATE }
    ensure(registrationCertificates.isNotEmpty()) { MissingRequiredRegistrationCertificate.asException() }
    ensure(registrationCertificates.size == 1) { MultipleRegistrationCertificates.asException() }
    val wrprcAttestation = registrationCertificates.first()
    ensure(wrprcAttestation.credentialIds == null) {
        malformedRegistrationCertificate("Provided credentialIds with registrations certificate while not expected")
    }
    val element = wrprcAttestation.data.value
    ensure(element is JsonPrimitive) {
        malformedRegistrationCertificate("Provided registration certificate is not a JSON primitive")
    }
    return element.jsonPrimitive.content
}

private fun malformedRegistrationCertificate(cause: String): AuthorizationRequestException =
    MalformedRegistrationCertificate(cause).asException()
