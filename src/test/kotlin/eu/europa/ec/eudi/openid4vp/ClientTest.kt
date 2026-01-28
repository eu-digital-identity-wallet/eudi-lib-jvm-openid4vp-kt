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

import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Test cases for [Client]
 */
internal class ClientTest {

    @Test
    internal fun `legal name`() {
        val certificate = ClientTest::class.java.classLoader.getResourceAsStream("certificates/certificates.jks")!!
            .use { inputStream ->
                KeyStore.getInstance("JKS").apply {
                    load(inputStream, "12345".toCharArray())
                }.getCertificate("verifierexample") as X509Certificate
            }
        val client = Client.X509SanDns("verifier.example.gr", certificate)
        assertEquals("verifierExample", client.legalName())
    }
}
