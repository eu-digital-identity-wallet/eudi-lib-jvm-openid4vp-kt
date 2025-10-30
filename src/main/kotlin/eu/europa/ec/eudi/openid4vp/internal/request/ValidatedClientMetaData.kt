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
package eu.europa.ec.eudi.openid4vp.internal.request

import eu.europa.ec.eudi.openid4vp.OpenId4VPSpec
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionSpecification
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName(OpenId4VPSpec.JWKS) val jwks: JsonObject? = null,
    @SerialName(OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED) val responseEncryptionMethodsSupported: List<String>? = null,
    @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED) @Required val vpFormatsSupported: VpFormatsSupported,
)

internal data class ValidatedClientMetaData(
    val responseEncryptionSpecification: ResponseEncryptionSpecification? = null,
    val vpFormatsSupported: VpFormatsSupported,
)
