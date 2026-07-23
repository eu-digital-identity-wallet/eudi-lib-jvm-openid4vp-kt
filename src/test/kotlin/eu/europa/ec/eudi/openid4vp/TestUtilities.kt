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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequestObject
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.assertThrows
import java.io.InputStream
import java.security.cert.X509Certificate
import kotlin.test.assertIs
import kotlin.test.fail

object TestUtilities

internal val json: Json by lazy { Json { ignoreUnknownKeys = true } }

internal fun load(f: String): InputStream =
    TestUtilities::class.java.classLoader.getResourceAsStream(f) ?: error("File $f not found")

@OptIn(ExperimentalSerializationApi::class)
internal fun readFileAsText(fileName: String): String {
    return json.decodeFromStream<JsonObject>(load(fileName)).jsonObject.toString()
}

internal fun Resolution.assertIsSuccess(): ResolvedRequestObject =
    when (this) {
        is Resolution.Success -> requestObject
        is Resolution.Invalid -> fail("Invalid resolution found while expected success\n$error")
    }

internal inline fun <reified T : AuthorizationRequestError> Resolution.assertIsInvalid(): T =
    when (this) {
        is Resolution.Invalid -> assertIs(error, "${T::class} error expected")
        else -> fail("Success resolution found while expected Invalid")
    }

internal fun randomKey(): Pair<JWSAlgorithm, ECKey> =
    JWSAlgorithm.ES256 to ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()

internal inline fun <reified E : AuthorizationRequestError> assertFailsWithError(block: () -> Unit): E {
    val exception = assertThrows<AuthorizationRequestException>(block)
    return assertIs<E>(exception.error)
}

internal fun UnvalidatedRequestObject.unsigned(): ReceivedRequest.Unsigned =
    ReceivedRequest.Unsigned(this)

internal fun genState(): String {
    return State().value
}

internal fun validateChain(chain: List<X509Certificate>): Boolean {
    return try {
        for (i in chain.indices)
            if (i > 0) chain[i - 1].verify(chain[i].publicKey)
        true
    } catch (_: Exception) {
        false
    }
}
