package com.lesmonades.security.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@RestController
public class ClientController {
    public WebClient webClient;

    public ClientController(WebClient.Builder builder) {
        this.webClient = builder
                .baseUrl("http://localhost:8080")
                .build();
    }

    @GetMapping("home")
    public Mono<String> home(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient client,
                             @AuthenticationPrincipal OidcUser oidcUser) {
        return Mono.just("""
        <h2> Access Token: %s </h2>
        <h2> Refresh Token: %s </h2>
        <h2> Id Token: %s </h2>
        <h2> Claims: %s </h2>
          """.formatted(client.getAccessToken().getTokenValue(),
                client.getRefreshToken().getTokenValue(),
                oidcUser.getIdToken().getTokenValue(),
                oidcUser.getClaims()));
    }

    @GetMapping("tasks")
    public Mono<String> getTasks(
            @RegisteredOAuth2AuthorizedClient("kitchen-client") OAuth2AuthorizedClient client) {
        return webClient
                .get()
                .uri("/tasks")
                .header("Authorization", "Bearer %s".formatted(client.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class);
    }

}
