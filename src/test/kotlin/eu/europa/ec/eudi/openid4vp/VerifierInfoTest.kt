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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.internal.request.requestObject
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class VerifierInfoTest {

    private val verifierInfoJwt =
        """
            eyJ0eXAiOiJyYy1ycCtqd3QiLCJ4NWMiOlsiTUlJQmRUQ0NBUnVnQXdJQkFnSVVIc1NtYkd1V0FWWlZYanFvaWRxQVZDbEd4NFl3Q2dZSUtvWkl6ajBFQXdJd0d6RVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQWVGdzB5TlRBek16QXhPVFU0TlRGYUZ3MHlOakF6TXpBeE9UVTROVEZhTUJzeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFTUVdDRVNGZDBZd205c0s4N1h4cXhEUDR3T0FhZEVLZ2NaRlZYN25wZTNBTEZrYmpzWFlaSnNUR2hWcDArQjVadFVhbzJOc3l6SkNLem5Qd1R6MndKY296MHdPekFhQmdOVkhSRUVFekFSZ2c5bWRXNXJaUzEzWVd4c1pYUXVaR1V3SFFZRFZSME9CQllFRk14bktMa0dpZmJUS3J4YkdYY0ZYSzZSRlFkM01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRRDRSaUxKZXVWRHJFSFN2a1BpUGZCdk14QVhSQzZQdUV4b3BVR0NGZGZOTFFJZ0hHU2E1dTVacVV0Q3JuTWlhRWFnZU83MXJqekJsb3YwWVVINCs2RUxpb1k9Il0sImFsZyI6IkVTMjU2In0.eyJwcml2YWN5X3BvbGljeSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vcHJpdmFjeS1wb2xpY3kiLCJwdXJwb3NlIjpbeyJsb2NhbGUiOiJlbi1VUyIsIm5hbWUiOiJUbyByZWdpc3RlciBhIG5ldyB1c2VyIn1dLCJjb250YWN0Ijp7IndlYnNpdGUiOiJodHRwczovL2V4YW1wbGUuY29tL2NvbnRhY3QiLCJlLW1haWwiOiJjb250YWN0QGV4YW1wbGUuY29tIiwicGhvbmUiOiIrMTIzNDU2Nzg5MCJ9LCJjcmVkZW50aWFscyI6W3siaWQiOiJwaWQiLCJmb3JtYXQiOiJkYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsiaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL2NyZWRlbnRpYWxzL3BpZC8xLjAiLCJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiXX0sImNsYWltcyI6W3sicGF0aCI6WyJmYW1pbHlfbmFtZSJdfSx7InBhdGgiOlsiZ2l2ZW5fbmFtZSJdfV19XSwiY3JlZGVudGlhbF9zZXRzIjpbeyJvcHRpb25zIjpbWyJwaWQiXV0sInJlcXVpcmVkIjp0cnVlLCJwdXJwb3NlIjpbeyJsb2NhbGUiOiJlbi1VUyIsIm5hbWUiOiJUbyByZWdpc3RlciBhIG5ldyB1c2VyIn1dfV0sInN1YiI6IkNOPURlbW8gUlAiLCJqdGkiOiI0MjFhMjgzOS1kNjMxLTQyMDMtOTBkMy1lN2Y2ZDJlYWFmODQiLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4Ijo0ODAwLCJ1cmkiOiJodHRwczovL2Z1bmtlLXdhbGxldC5kZS9zdGF0dXMtbWFuYWdlbWVudC9zdGF0dXMtbGlzdCJ9fSwicHVibGljX2JvZHkiOmZhbHNlLCJlbnRpdGxlbWVudHMiOltdLCJzZXJ2aWNlcyI6W119.r3TDzMGbrzUK_LrNWu_1I4f0cELdThZvRHNHB_Q8ePMhbFPxNQ7jGArKIX4_O529D1X2hUeuuSgyW61SVNL0jA
        """.trimIndent()

    private val authorizationRequest: SignedJWT by lazy {
        SignedJWT(
            JWSHeader.parse(
                """
                {
                    "typ": "oauth-authz-req+jwt",
                    "alg": "ES256",
                    "x5c": [
                        "MIIB7DCCAZOgAwIBAgIUHj8qsBiHUZvnEpGep978NYQNjpMwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjAeFw0yNTA0MTExNzUyMzNaFw0yNjA0MTExNzUyMzNaMBIxEDAOBgNVBAMMB0RlbW8gUlAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUJPGhaaT8Ja+tpnVUjUwhZVq3LDV75EcBXGLpaW/g4ghxfDTQZRM/3TD2gGVNnJN6m7//0FZg9lzlKVbmIs1Go4G9MIG6MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQTMBGCD2Z1bmtlLXdhbGxldC5kZTAvBgNVHR8EKDAmMCSgIqAghh5odHRwczovL2Z1bmtlLXdhbGxldC5kZS9jYS9jcmwwHQYDVR0OBBYEFK4YKERkZXP+tG9eDRaVdEBJ6h22MB8GA1UdIwQYMBaAFMxnKLkGifbTKrxbGXcFXK6RFQd3MAoGCCqGSM49BAMCA0cAMEQCIQD+YXfii0tzkdFx3iYa7isavb1sVh3icCSb+BBxRLJu7gIfTt23DkhfCa/5ogATGw5axmXaON1JPR89P68UMPPWNw=="
                    ]
                }
                """.trimIndent(),
            ),
            JWTClaimsSet.parse(
                """
                    {
                        "response_type": "vp_token",
                        "client_id": "x509_san_dns:funke-wallet.de",
                        "response_uri": "https://funke-wallet.de/oid4vp/response",
                        "response_mode": "direct_post.jwt",
                        "nonce": "860303407528324526871313",
                        "dcql_query": {
                            "credentials": [
                                {
                                    "id": "pid",
                                    "format": "dc+sd-jwt",
                                    "meta": {
                                        "vct_values": [
                                            "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
                                            "urn:eu.europa.ec.eudi:pid:1"
                                        ]
                                    },
                                    "claims": [
                                        {
                                            "path": [
                                                "family_name"
                                            ]
                                        },
                                        {
                                            "path": [
                                                "given_name"
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                        "client_metadata": {
                            "jwks": {
                                "keys": [
                                    {
                                        "kty": "EC",
                                        "crv": "P-256",
                                        "x": "zkTLfa_56qNjkw8iFQlEt_4q1gRJi5JIwuUsDH74L1A",
                                        "y": "-KmZ6aBGn-UyerOOhsg81061J9IIvsZ6dzu7AY3gsWc",
                                        "kid": "zDnaewYUFAkUL6Ha5Q1H9xo8kMsGG8cGNY3aX9G7pkuKi1WT9",
                                        "use": "enc"
                                    }
                                ]
                            },
                            "vp_formats": {
                                "mso_mdoc": {
                                    "alg": [
                                        "EdDSA",
                                        "ES256",
                                        "ES384"
                                    ]
                                },
                                "vc+sd-jwt": {
                                    "kb-jwt_alg_values": [
                                        "EdDSA",
                                        "ES256",
                                        "ES384",
                                        "ES256K"
                                    ],
                                    "sd-jwt_alg_values": [
                                        "EdDSA",
                                        "ES256",
                                        "ES384",
                                        "ES256K"
                                    ]
                                },
                                "dc+sd-jwt": {
                                    "kb-jwt_alg_values": [
                                        "EdDSA",
                                        "ES256",
                                        "ES384",
                                        "ES256K"
                                    ],
                                    "sd-jwt_alg_values": [
                                        "EdDSA",
                                        "ES256",
                                        "ES384",
                                        "ES256K"
                                    ]
                                }
                            },
                            "authorization_encrypted_response_alg": "ECDH-ES",
                            "authorization_encrypted_response_enc": "A256GCM",
                            "client_name": "German Registrar",
                            "response_types_supported": [
                                "vp_token"
                            ]
                        },
                        "state": "764143516933320540744584",
                        "aud": "https://funke-wallet.de",
                        "exp": 1746538484,
                        "iat": 1746538184,
                        "verifier_info": [
                            {
                                "format": "jwt",
                                "data": "$verifierInfoJwt"
                            }
                        ]
                    }
                """.trimIndent(),
            ),
        )
    }

    @Test
    fun testParsing() = runTest {
        val unvalidatedRequestObject = authorizationRequest.requestObject().also { println(it) }

        val verifierInfo = run {
            val unvalidatedVerifierInfo = assertNotNull(unvalidatedRequestObject.verifierInfo)
            VerifierInfo.fromJson(unvalidatedVerifierInfo.value).getOrThrow()
        }

        assertEquals(1, verifierInfo.attestations.size)

        val attestation = verifierInfo.attestations.first()
        assertEquals(VerifierInfo.Attestation.Format.Jwt, attestation.format)
        assertEquals(JsonPrimitive(verifierInfoJwt), attestation.data.value)
        assertNull(attestation.credentialIds)
    }
}
