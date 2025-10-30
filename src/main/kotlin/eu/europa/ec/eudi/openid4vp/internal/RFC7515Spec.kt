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
package eu.europa.ec.eudi.openid4vp.internal

import eu.europa.ec.eudi.openid4vp.runCatchingCancellable
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

internal object RFC7515Spec {

    const val JWS_JSON_SYNTAX_PAYLOAD = "payload"
    const val JWS_JSON_SYNTAX_SIGNATURE = "signature"
    const val JWS_JSON_SYNTAX_SIGNATURES = "signatures"
    const val JWS_JSON_SYNTAX_HEADER = "header"
    const val JWS_JSON_SYNTAX_PROTECTED_HEADER = "protected"
}

@JvmInline
@Serializable(with = Base64UrlNoPaddingSerializer::class)
internal value class Base64UrlNoPadding private constructor(val value: String) {

    override fun toString(): String = value

    companion object {

        operator fun invoke(value: String): Result<Base64UrlNoPadding> = runCatchingCancellable {
            require(value.isNotBlank()) { "Value must not be empty" }
            // Try to parse the passed value as base64 url encoded no-padding string
            base64UrlNoPadding.decode(value)
            Base64UrlNoPadding(value)
        }
    }
}

@Serializable
internal data class Signature(
    val header: JsonObject? = null,
    val protected: Base64UrlNoPadding? = null,
    val signature: Base64UrlNoPadding,
) {
    init {
        require(header != null || protected != null) {
            "At least one of protected or un protected headers must be set."
        }
    }
}

@Serializable(with = JwsJsonSerializer::class)
internal sealed interface JwsJson {

    val payload: Base64UrlNoPadding

    @Serializable
    data class General(
        override val payload: Base64UrlNoPadding,
        val signatures: List<Signature>,
    ) : JwsJson {
        init {
            require(signatures.isNotEmpty()) { "At least one signature is required" }
        }
    }

    @Serializable
    data class Flattened(
        val header: JsonObject? = null,
        val protected: Base64UrlNoPadding? = null,
        override val payload: Base64UrlNoPadding,
        val signature: Base64UrlNoPadding,
    ) : JwsJson {
        init {
            require(header != null || protected != null) {
                "At least one of protected or un protected headers must be set."
            }
        }
    }

    companion object {

        /**
         * Parses an input string representing a JWS in compact form into a [JwsJson.Flattened] object.
         */
        fun from(compact: String): Result<JwsJson> = runCatchingCancellable {
            require(compact.isNotBlank()) { "Input must not be empty" }
            compact.split(".").let { parts ->
                require(parts.size == 3) { "Input must be a JWS in compact form" }
                val jwsJsonObject = buildJsonObject {
                    put(RFC7515Spec.JWS_JSON_SYNTAX_PROTECTED_HEADER, parts[0])
                    put(RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD, parts[1])
                    put(RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE, parts[2])
                }
                Json.decodeFromJsonElement<JwsJson>(jwsJsonObject)
            }
        }

        fun JwsJson.flatten(): List<Flattened> = when (this) {
            is Flattened -> listOf(this)
            is General -> signatures.map {
                Flattened(
                    header = it.header,
                    protected = it.protected,
                    payload = payload,
                    signature = it.signature,
                )
            }
        }
    }
}

internal object JwsJsonSerializer : JsonContentPolymorphicSerializer<JwsJson>(JwsJson::class) {

    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<JwsJson> = when {
        RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURES in element.jsonObject -> JwsJson.General.serializer()
        RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE in element.jsonObject -> JwsJson.Flattened.serializer()
        else -> throw IllegalArgumentException("Unsupported JWS JSON format")
    }
}

internal object Base64UrlNoPaddingSerializer : KSerializer<Base64UrlNoPadding> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64UrlNoPadding", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Base64UrlNoPadding = try {
        Base64UrlNoPadding(decoder.decodeString()).getOrThrow()
    } catch (t: Exception) {
        throw SerializationException("Unable to decode base64 url-safe", t)
    }

    override fun serialize(encoder: Encoder, value: Base64UrlNoPadding) =
        encoder.encodeString(value.toString())
}

internal inline fun <reified T> Base64UrlNoPadding.decodeAs(): T =
    jsonSupport.decodeFromString(
        base64UrlNoPadding.decode(value).decodeToString(),
    )

internal inline fun <reified T> JwsJson.decodePayloadAs(): T = payload.decodeAs()
