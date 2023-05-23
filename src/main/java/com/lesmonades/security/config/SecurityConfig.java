package com.lesmonades.security.config;

import com.lesmonades.security.controller.OAuthController;
import com.lesmonades.security.config.oauth.CustomAuthorizationRedirectFilter;
import com.lesmonades.security.config.oauth.CustomAuthorizationRequestResolver;
import com.lesmonades.security.config.oauth.CustomAuthorizedClientService;
import com.lesmonades.security.config.oauth.CustomStatelessAuthorizationRequestRepository;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.SneakyThrows;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final OAuthController oauthController;
    private final CustomAuthorizedClientService customAuthorizedClientService;
    private final CustomAuthorizationRedirectFilter customAuthorizationRedirectFilter;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
    private final CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;

    public SecurityConfig(OAuthController oauthController, CustomAuthorizedClientService customAuthorizedClientService, CustomAuthorizationRedirectFilter customAuthorizationRedirectFilter, CustomAuthorizationRequestResolver customAuthorizationRequestResolver, CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository) {
        this.oauthController = oauthController;
        this.customAuthorizedClientService = customAuthorizedClientService;
        this.customAuthorizationRedirectFilter = customAuthorizationRedirectFilter;
        this.customAuthorizationRequestResolver = customAuthorizationRequestResolver;
        this.customStatelessAuthorizationRequestRepository = customStatelessAuthorizationRequestRepository;
    }

    @Bean
    @SneakyThrows
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http.authorizeHttpRequests(auth -> {
//            auth.requestMatchers("/").permitAll();
//            auth.anyRequest().authenticated();
//        }).oauth2Login(withDefaults()).build();
        http
                // Endpoint protection
                .authorizeHttpRequests(config -> {
                    config.anyRequest().permitAll();
                })
                // Disable "JSESSIONID" cookies
                .sessionManagement(config -> {
                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // OAuth2 (social logins)
                .oauth2Login(config -> {
                    config.authorizationEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
                        subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
                        subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
                    });
                    config.redirectionEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthController.CALLBACK_BASE_URL + "/*");
                    });
                    config.authorizedClientService(this.customAuthorizedClientService);
                    config.successHandler(this.oauthController::oauthSuccessResponse);
                    config.failureHandler(this.oauthController::oauthFailureResponse);
                })
                // Filters
                .addFilterBefore(this.customAuthorizationRedirectFilter, OAuth2AuthorizationRequestRedirectFilter.class)
                // Auth exceptions
                .exceptionHandling(config -> {
                    config.accessDeniedHandler(this::accessDenied);
                    config.authenticationEntryPoint(this::accessDenied);
                });
        return http.build();
    }

    @SneakyThrows
    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

}
