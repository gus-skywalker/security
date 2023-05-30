/*
package com.lesmonades.security.controller;

import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class AuthController {

    private WebClient webClient;

    public AuthController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping(value = "/test-redirect")
    public String[] getArticles(
            @RegisteredOAuth2AuthorizedClient("kitchen-client-authorization-code") OAuth2AuthorizedClient authorizedClient
    ) {
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8080/api/food")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }



}*/
