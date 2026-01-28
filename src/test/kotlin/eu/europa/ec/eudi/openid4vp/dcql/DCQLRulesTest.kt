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
package eu.europa.ec.eudi.openid4vp.dcql

import kotlin.test.Test
import kotlin.test.fail

class DCQLRulesTest {

    @Test
    fun credentialQueryIdMustBeNonEemptyStringAlphanumericUnderscoreOrHyphen() {
        val illegalIds = listOf(
            "",
            "@@123a",
            "^&())_",
        )
        illegalIds.forEach {
            try {
                QueryId(it)
                fail("Accepted as id $it")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun whenCredentialsIsEmptyAnExceptionIsRaised() {
        try {
            Credentials(emptyList())
            fail("DCQL cannot have an empty credentials attribute")
        } catch (_: IllegalArgumentException) {
            // ok
        }
    }

    @Test
    fun whenCredentialsContainsEntriesWithTheSameIdAnExceptionIsRaised() {
        try {
            val id = QueryId("id")
            Credentials(
                CredentialQuery.mdoc(id, DCQLMetaMsoMdocExtensions(MsoMdocDocType("foo"))),
                CredentialQuery.sdJwtVc(id, DCQLMetaSdJwtVcExtensions(vctValues = listOf("bar"))),
            )
            fail("CredentialQuery ids must be unique")
        } catch (_: IllegalArgumentException) {
            // ok
        }
    }

    @Test
    fun whenCredentialsSetIsEmptyAnExceptionIsRaised() {
        try {
            Credentials(
                CredentialQuery.mdoc(
                    QueryId("id1"),
                    DCQLMetaMsoMdocExtensions(MsoMdocDocType("foo")),
                    claimSets = emptyList(),
                ),
            )
            fail("credentialSets, if provided, cannot be empty")
        } catch (_: IllegalArgumentException) {
            // ok
        }
    }
}
