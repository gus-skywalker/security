package com.lesmonades.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
public class SecurityController {

    @GetMapping
    public String getUser() {
        return "O escolhido foi você. Salame migue";
    }

    @PostMapping
    public String postUser() {
        return "Eu to funcionando!";
    }
}
