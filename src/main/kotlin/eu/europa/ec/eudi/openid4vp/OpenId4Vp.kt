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
package eu.europa.ec.eudi.openid4vp

import eu.europa.ec.eudi.openid4vp.OpenId4Vp.Companion.invoke
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcher
import io.ktor.client.*

/**
 * An interface providing support for handling an OAuth2.0 request that represents OpenId4VP authorization.
 *
 * To obtain an instance of [OpenId4Vp], method [invoke] can be used.
 *
 * @see AuthorizationRequestResolver
 * @see Dispatcher
 */
interface OpenId4Vp : AuthorizationRequestResolver, Dispatcher, ErrorDispatcher {

    companion object {

        /**
         * Factory method to create a [OpenId4Vp].
         *
         * @param openId4VPConfig wallet's configuration
         * @param httpClient A Ktor http client. This can be used to configure ktor
         * to use a specific engine.
         *
         * @return a [OpenId4Vp]
         */
        operator fun invoke(
            openId4VPConfig: OpenId4VPConfig,
            httpClient: HttpClient,
        ): OpenId4Vp {
            val requestResolver = DefaultAuthorizationRequestResolver(openId4VPConfig, httpClient)
            val dispatcher = DefaultDispatcher(httpClient)
            return object :
                AuthorizationRequestResolver by requestResolver,
                Dispatcher by dispatcher,
                ErrorDispatcher by dispatcher,
                OpenId4Vp {}
        }
    }
}

@Deprecated("Use OpenId4Vp instead", ReplaceWith("OpenId4Vp"))
typealias SiopOpenId4Vp = OpenId4Vp
