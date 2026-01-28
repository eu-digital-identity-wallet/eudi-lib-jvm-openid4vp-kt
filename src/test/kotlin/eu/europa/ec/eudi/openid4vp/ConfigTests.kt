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

import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.Test
import kotlin.test.assertFailsWith

class ConfigTests {

    @Test
    fun `SupportedVpFormats requires at least one SupportedVpFormat`() {
        assertDoesNotThrow {
            VpFormatsSupported(
                null,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            )
        }

        assertDoesNotThrow {
            VpFormatsSupported(VpFormatsSupported.SdJwtVc.HAIP, null)
        }

        assertDoesNotThrow {
            VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            )
        }

        assertFailsWith<IllegalArgumentException> {
            VpFormatsSupported(null, null)
        }
    }
}
