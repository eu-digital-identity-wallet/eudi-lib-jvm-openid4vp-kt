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
package eu.europa.ec.eudi.openid4vp

import kotlinx.serialization.Serializable

@Serializable
@JvmInline
value class Format(val value: String) {
    init {
        require(value.isNotBlank()) { "Format cannot be blank" }
    }

    override fun toString(): String = value

    companion object {
        val MsoMdoc: Format get() = Format(OpenId4VPSpec.FORMAT_MSO_MDOC)
        val SdJwtVc: Format get() = Format(OpenId4VPSpec.FORMAT_SD_JWT_VC)
        val W3CJwtVcJson: Format get() = Format(OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT)
    }
}
