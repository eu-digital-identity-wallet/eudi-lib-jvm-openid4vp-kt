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

import com.nimbusds.jose.util.JSONObjectUtils
import kotlinx.serialization.json.*

internal val jsonSupport = Json {
    prettyPrint = false
    ignoreUnknownKeys = true
}

internal fun JsonObject.requiredString(name: String): String {
    val value = this[name]
    requireNotNull(value) { "Missing required property '$name'" }
    require(value is JsonPrimitive && value.isString) { "Property '$name' is not a string'" }
    return value.jsonPrimitive.content
}

internal fun JsonObject.requiredStringArray(name: String): List<String> {
    val value = this[name]
    requireNotNull(value) { "Missing required property '$name'" }
    require(value is JsonArray && value.all { it is JsonPrimitive && it.isString }) {
        "Property '$name' is not an array or contains non string values"
    }
    return value.jsonArray.map { it.jsonPrimitive.content }
}

internal fun JsonObject.optionalStringArray(name: String): List<String>? {
    val value = this[name]
    return value?.let {
        require(value is JsonArray && value.all { it is JsonPrimitive && it.isString }) {
            "Property '$name' is not an array or contains non string values"
        }
        value.jsonArray.map { it.jsonPrimitive.content }
    }
}

internal fun Map<String, *>.toJsonObject(): JsonObject = jsonSupport.decodeFromString(JSONObjectUtils.toJSONString(this))
