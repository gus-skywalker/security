package com.lesmonades.socialauth.controller;

import com.lesmonades.socialauth.helpers.AuthenticationHelper;
import com.lesmonades.socialauth.helpers.CookieHelper;
import com.lesmonades.socialauth.service.AccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Controller;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
@AllArgsConstructor
public class OAuthController {

    /**
     * Default = {@value OAuth2AuthorizationRequestRedirectFilter#DEFAULT_AUTHORIZATION_REQUEST_BASE_URI}
     * <p>
     * For instance:
     * - /oauth2/authorization/auth0
     * - /oauth2/authorization/facebook
     * - /oauth2/authorization/google
     */
    public static final String AUTHORIZATION_BASE_URL = "/oauth2/authorization";

    /**
     * Default = {@value OAuth2LoginAuthenticationFilter#DEFAULT_FILTER_PROCESSES_URI}
     * <p>
     * For instance:
     * - /oauth2/callback/auth0
     * - /oauth2/callback/facebook
     * - /oauth2/callback/google
     */
    public static final String CALLBACK_BASE_URL = "/oauth2/callback";

    public static final String OAUTH_COOKIE_NAME = "OAUTH";
    public static final String SESSION_COOKIE_NAME = "SESSION";

    private final AccountService accountService;

    @SneakyThrows
    public void oauthRedirectResponse(HttpServletRequest request, HttpServletResponse response, String url) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"redirectUrl\": \"%s\" }".formatted(url));
    }

    @SneakyThrows
    public void oauthSuccessCallback(OAuth2AuthorizedClient client, Authentication authentication) {
        // You can grab the access + refresh tokens as well via the "client"
        Map<String, Object> socialUserInfo = new HashMap<>();
        if(client.getClientRegistration().getRegistrationId().equals("github")) {
            socialUserInfo.putAll(((DefaultOAuth2User) authentication.getPrincipal()).getAttributes());
        } else {
            socialUserInfo.putAll(((DefaultOidcUser) authentication.getPrincipal()).getClaims()); // Other Social Logins
        }
        UUID accountId = this.accountService.findOrRegisterAccount(
                authentication.getName(),
                authentication.getName().split("\\|")[0],
                socialUserInfo
        );
        AuthenticationHelper.attachAccountId(authentication, accountId.toString());
    }

    @SneakyThrows
    public void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String accountId = AuthenticationHelper.retrieveAccountId(authentication);
        response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME));
        response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateCookie(SESSION_COOKIE_NAME, accountId, Duration.ofDays(1)));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"status\": \"success\" }");
    }

    @SneakyThrows
    public void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME));
        response.getWriter().write("{ \"status\": \"failure\" }");
    }

}
