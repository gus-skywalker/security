package com.lesmonades.socialauth.config;

import com.lesmonades.socialauth.controller.OAuthController;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizationRedirectFilter;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizationRequestResolver;
import com.lesmonades.socialauth.config.oauth.CustomAuthorizedClientService;
import com.lesmonades.socialauth.config.oauth.CustomStatelessAuthorizationRequestRepository;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.SneakyThrows;

import org.springframework.context.annotation.Configuration;

import org.springframework.http.MediaType;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

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


//    @Bean
//    @SneakyThrows
//    SecurityFilterChain securityFilterChain(HttpSecurity http) {
//        http
//                .authorizeHttpRequests(authorize -> {
//                    authorize.anyRequest().permitAll();
//                })
//                // Disable "JSESSIONID" cookies
//                .sessionManagement(config -> {
//                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//                })
//                // OAuth2 (social logins)
//                .oauth2Login(oauth2Login -> {
//                    oauth2Login.authorizationEndpoint(subconfig -> {
//                                subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
//                                subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
//                                subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
//                    });
//                    oauth2Login.redirectionEndpoint(subconfig -> {
//                        subconfig.baseUri(OAuthController.CALLBACK_BASE_URL + "/*");
//                    });
//                    oauth2Login.authorizedClientService(this.customAuthorizedClientService);
//                    oauth2Login.successHandler(this.oauthController::oauthSuccessResponse);
//                    oauth2Login.failureHandler(this.oauthController::oauthFailureResponse);
//                })
//                // Filters
//                .addFilterBefore(this.customAuthorizationRedirectFilter, OAuth2AuthorizationRequestRedirectFilter.class)
//                // Auth exceptions
//                .exceptionHandling(exception -> {
//                    exception.accessDeniedHandler(this::accessDenied);
//                    exception.authenticationEntryPoint(this::accessDenied);
//                }).oauth2Client();
//        return http.build();
//    }

    @SneakyThrows
    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

}
