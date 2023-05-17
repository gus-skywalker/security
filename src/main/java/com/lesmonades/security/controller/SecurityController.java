package com.lesmonades.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String home() {
        return "Home - O escolhido foi você. Salame migue";
    }

    @GetMapping("/secured")
    public String secured() {
        return "Eu to funcionando de forma segura!";
    }
}
