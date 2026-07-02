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

import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverDCApi
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverHttp
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDCApiResponseBuilder
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherOverHttp
import io.ktor.client.*

/**
 * An interface providing support for handling an OAuth2.0 request that represents OpenId4VP authorization coming via the HTTP channel or
 * the Digital Credentials API.
 *
 * To obtain an instance of [OpenId4Vp], either method [OpenId4Vp.overHttp()] or [OpenId4Vp.overDcApi()] can be used.
 *
 * @see AuthorizationRequestOverHttpResolver
 * @see AuthorizationRequestOverDCApiResolver
 * @see DispatcherOverHttp
 * @see DCApiResponseBuilder
 */
sealed interface OpenId4Vp {

    interface OverRedirects : AuthorizationRequestOverHttpResolver, DispatcherOverHttp, ErrorDispatcher, OpenId4Vp
    interface OverDcAPI : AuthorizationRequestOverDCApiResolver, DCApiResponseBuilder, OpenId4Vp

    companion object {

        fun overRedirects(
            openId4VPConfig: OpenId4VPConfig,
            httpClient: HttpClient,
        ): OverRedirects {
            val requestResolver = DefaultRequestResolverOverHttp(openId4VPConfig, httpClient)
            val dispatcher = DefaultDispatcherOverHttp(httpClient)
            return object :
                AuthorizationRequestOverHttpResolver by requestResolver,
                DispatcherOverHttp by dispatcher,
                ErrorDispatcher by dispatcher,
                OverRedirects {}
        }

        fun overDcApi(
            openId4VPConfig: OpenId4VPConfig,
            httpClient: HttpClient,
        ): OverDcAPI {
            val requestResolver = DefaultRequestResolverOverDCApi(openId4VPConfig)
            val dispatcher = DefaultDCApiResponseBuilder()
            return object :
                AuthorizationRequestOverDCApiResolver by requestResolver,
                DCApiResponseBuilder by dispatcher,
                OverDcAPI {}
        }
    }
}
