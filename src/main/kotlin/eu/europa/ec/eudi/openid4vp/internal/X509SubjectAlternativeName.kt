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
package eu.europa.ec.eudi.openid4vp.internal

import eu.europa.ec.eudi.openid4vp.runCatchingCancellable
import java.security.cert.X509Certificate

fun X509Certificate.sanOfUniformResourceIdentifier(): Result<List<String>> =
    san(X509SubjectAlternativeNameType.UniformResourceIdentifier)
fun X509Certificate.sanOfDNSName(): Result<List<String>> =
    san(X509SubjectAlternativeNameType.DNSName)

private fun X509Certificate.san(type: X509SubjectAlternativeNameType): Result<List<String>> = runCatchingCancellable {
    buildList {
        subjectAlternativeNames
            ?.filter { subjectAltNames -> !subjectAltNames.isNullOrEmpty() && subjectAltNames.size == 2 }
            ?.forEach { entry ->
                val altNameType = entry[0] as Int
                entry[1].takeIf { altNameType == type.asInt() }?.let { add(it as String) }
            }
    }
}

private enum class X509SubjectAlternativeNameType {
    UniformResourceIdentifier,
    DNSName,
}

// https://www.rfc-editor.org/rfc/rfc5280.html
private fun X509SubjectAlternativeNameType.asInt() = when (this) {
    X509SubjectAlternativeNameType.UniformResourceIdentifier -> 6
    X509SubjectAlternativeNameType.DNSName -> 2
}
