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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

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
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().issuer("http://auth-server:9000").build();
//    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("kitchen-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/kitchen-client-oidc")
                .redirectUri("http://127.0.0.1:8082/callback.html")
//                .redirectUri("https://oidcdebugger.com/debug")
//                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .postLogoutRedirectUri("http://127.0.0.1:8082/logged-out")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("users.read")
                .scope("users.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    @SneakyThrows
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
                .authorizeHttpRequests(authorize -> {
                    authorize.anyRequest().permitAll();
                })
                // Disable "JSESSIONID" cookies
                .sessionManagement(config -> {
                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // OAuth2 (social logins)
                .oauth2Login(oauth2Login -> {
                    oauth2Login.authorizationEndpoint(subconfig -> {
                                subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
                                subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
                                subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
                    });
                    oauth2Login.redirectionEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthController.CALLBACK_BASE_URL + "/*");
                    });
                    oauth2Login.authorizedClientService(this.customAuthorizedClientService);
                    oauth2Login.successHandler(this.oauthController::oauthSuccessResponse);
                    oauth2Login.failureHandler(this.oauthController::oauthFailureResponse);
                })
                // Filters
                .addFilterBefore(this.customAuthorizationRedirectFilter, OAuth2AuthorizationRequestRedirectFilter.class)
                // Auth exceptions
                .exceptionHandling(exception -> {
                    exception.accessDeniedHandler(this::accessDenied);
                    exception.authenticationEntryPoint(this::accessDenied);
                })
                .oauth2Client(withDefaults());;
        return http.build();
    }

    @SneakyThrows
    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

}
