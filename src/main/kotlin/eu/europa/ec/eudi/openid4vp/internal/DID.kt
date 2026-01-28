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
import java.net.URI

@JvmInline
internal value class AbsoluteDIDUrl private constructor(val uri: URI) {

    override fun toString(): String = uri.toString()

    companion object {

        fun parse(s: String): Result<AbsoluteDIDUrl> = runCatchingCancellable {
            fun isNotDID() = DID.parse(s).getOrNull() == null
            if (DID_URL_SYNTAX.matches(s) && isNotDID())
                AbsoluteDIDUrl(URI.create(s))
            else error("Not a valid DID URL: $s")
        }
    }
}

@JvmInline
internal value class DID private constructor(val uri: URI) {

    override fun toString(): String = uri.toString()

    companion object {
        fun parse(s: String): Result<DID> = runCatchingCancellable {
            if (DID_SYNTAX.matches(s)) DID(URI.create(s))
            else error("Not a DID")
        }
    }
}

@Suppress("kotlin:S5843")
private val DID_URL_SYNTAX = (
    "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)" +
        "*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+(/(([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)*)" +
        "*(\\?(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))" +
        "?(#(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?$"
    ).toRegex()

@Suppress("kotlin:S5843")
private val DID_SYNTAX =
    "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+$".toRegex()
