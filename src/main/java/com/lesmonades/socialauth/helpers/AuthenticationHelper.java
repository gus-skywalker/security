package com.lesmonades.socialauth.helpers;

import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

public class AuthenticationHelper {

    public static void attachAccountId(Authentication authentication, String accountId) {
        Object originalDetails = authentication.getDetails();
        if (originalDetails instanceof Details details) {
            details.setAccountId(accountId);
        } else {
            Details details = new Details()
                    .setOriginal(originalDetails)
                    .setAccountId(accountId);
            ((OAuth2AuthenticationToken) authentication).setDetails(details);
        }
    }

    public static String retrieveAccountId(Authentication authentication) throws OAuth2AuthenticationException {
        Details details = (Details) authentication.getDetails();
        return details.getAccountId();
//        DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal(); // Used for other Social Logins besides GitHub
        // oidcUser.getAttribute("name");
    }

    @Data
    @Accessors(chain = true)
    private static class Details {

        private Object original;
        private String accountId;

    }

}
