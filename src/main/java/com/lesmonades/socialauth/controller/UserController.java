package com.lesmonades.socialauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserController {

    @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }

    @GetMapping("/")
    public String home() {
        return "Home - O escolhido foi você. Salame migue";
    }

    @GetMapping("/secured")
    public String secured() {
        return "Eu to funcionando de forma segura!";
    }
}
