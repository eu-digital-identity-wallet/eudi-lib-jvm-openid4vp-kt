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

import eu.europa.ec.eudi.openid4vp.internal.mapError
import eu.europa.ec.eudi.openid4vp.runCatchingCancellable
import java.net.URI
import java.net.URL

/**
 * Convenient method for parsing a string into a [URL]
 * Also, enforcing [URL] to be HTTPS
 */
internal fun String.asHttpsURL(onError: (Throwable) -> Throwable = { it }): Result<URL> =
    runCatchingCancellable {
        val url = URL(this)
        url.requireHttps().getOrThrow()
    }.mapError(onError)

/**
 * Convenient method for parsing a string into a [URI]
 * Also, enforcing [URL] to be HTTPS
 */
internal fun String.asHttpsURI(onError: (Throwable) -> Throwable = { it }): Result<URI> =
    runCatchingCancellable {
        val uri = URI(this)
        uri.requireHttps().getOrThrow()
    }.mapError(onError)

private fun URL.requireHttps(onError: (Throwable) -> Throwable = { it }): Result<URL> =
    if (protocol.equals("https", ignoreCase = true)) {
        Result.success(this)
    } else {
        Result.failure(onError(IllegalArgumentException("URL must use HTTPS: $this")))
    }

private fun URI.requireHttps(onError: (Throwable) -> Throwable = { it }): Result<URI> =
    if (scheme.equals("https", ignoreCase = true)) {
        Result.success(this)
    } else {
        Result.failure(onError(IllegalArgumentException("URL must use HTTPS: $this")))
    }
