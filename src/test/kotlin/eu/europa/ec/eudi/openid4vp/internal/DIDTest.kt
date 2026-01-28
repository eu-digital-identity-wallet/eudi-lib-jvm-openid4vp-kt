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

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DIDTest {
    private val sampleDidJwk =
        """
           did:jwk:
           eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI
           1Njpnc0w0VTRxX1J6VFhRckpwQUNnZGkwb1lCdUV1QjNZNWZFanhDd1NPUFlBIiwia3
           R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsImFsZyI6IkVTMzg0IiwieCI6ImEtRWV5T2hlR
           UNWcDJqRkdVRTNqR0RCNlAzVV80S0lyZHRzTU9RQXFQN0NBMlVvV3NERG1nOWdJUVhi
           OEthd0ciLCJ5Ijoib3cxWDJ6VFVRaG12elY4NnpHdGhKc0xLeDE2MmhmSmxmN1p0OTF
           YUnZBTzRScE4zR2RGaVl3Tmc0NXJWUmlUcSJ9
        """.trimIndent().replace("\n", "")

    @Test
    fun `valid should DIDs should be parsed`() {
        listOf(
            "did:ethr:mainnet:0x3b0bc51ab9de1e5b7b6e34e5b960285805c41736",
            "did:dns:danubetech.com",
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            sampleDidJwk,
            "did:ebsi:ziE2n8Ckhi6ut5Z8Cexrihd",
            "did:eosio:4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11:caleosblocks",
        ).forEach {
            assertNotNull(DID.parse(it).getOrNull(), "Failed to parse $it")
        }
    }

    @Test
    fun `invalid should DIDs should not be parsed`() {
        listOf(
            "didethr:mainnet:0x3b0bc51ab9de1e5b7b6e34e5b960285805c41736",
            "dns:danubetech.com",
            "did:   :zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            "did:jwk:   ",
            "did:example:123?service=agent&relativeRef=/credentials#degree",
            "did:example:123?service=agent&relativeRef=/credentials",
            "did:eosio:4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11:caleosblocks#123",
        ).forEach {
            assertNull(DID.parse(it).getOrNull(), "Parsed should fail for $it")
        }
    }

    @Test
    fun `valid should DIDs should not be parsed as DIDURLs`() {
        listOf(
            "did:dns:danubetech.com",
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            sampleDidJwk,
            "did:ebsi:ziE2n8Ckhi6ut5Z8Cexrihd",
            "did:ethr:mainnet:0x3b0bc51ab9de1e5b7b6e34e5b960285805c41736",
        ).forEach {
            assertNull(AbsoluteDIDUrl.parse(it).getOrNull(), "Parsed should fail for $it")
        }
    }

    @Test
    fun `valid should DID URLSs should be parsed as DIDURLs`() {
        listOf(
            "did:ethr:mainnet:0x3b0bc51ab9de1e5b7b6e34e5b960285805c41736#controller",
            "did:dns:danubetech.com#z6MkjvBkt8ETnxXGBFPSGgYKb43q7oNHLX8BiYSPcXVG6gY6",
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            "did:ebsi:ziE2n8Ckhi6ut5Z8Cexrihd#key-1",
            "did:example:123?service=agent&relativeRef=/credentials#degree",
            "did:eosio:4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11:caleosblocks#123",
        ).forEach {
            assertNotNull(AbsoluteDIDUrl.parse(it).getOrNull(), "Failed to parse $it")
        }
    }
}
