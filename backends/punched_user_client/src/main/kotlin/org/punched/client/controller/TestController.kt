package org.punched.client.controller

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono

@RestController
class TestController {
    @GetMapping("/version")
    fun version(): String {
        return "version"
    }


    @Autowired
    private lateinit var webClient: WebClient

    @GetMapping("/client/test")
    fun getArticles(
        @RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code") authorizedClient: OAuth2AuthorizedClient
    ): Map<String, Any> {
        return this.webClient
            .get()
            .uri("http://127.0.0.1:8090/resource/test")  // Assuming resource server runs on 8090
            .attributes(oauth2AuthorizedClient(authorizedClient))
            .retrieve()
            .bodyToMono<Map<String, Any>>()
            .block() ?: emptyMap()
    }
}