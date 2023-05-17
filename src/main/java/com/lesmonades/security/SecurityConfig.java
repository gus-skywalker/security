package com.lesmonades.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
@Configuration
@Order(1)
public class SecurityConfig {

    @Value("${user.oauth.user.username}")
    private String username;
    @Value("${user.oauth.user.password}")
    private String password;

    protected void configure(HttpSecurity http) throws Exception {
        String[] adminEndpoints = {"/health", "/env", "/metrics/**", "/trace", "/dump", "/flyway", "/jolokia/**",
                "/info", "/actuator", "/refresh", "/resume", "/heapdump", "/configprops", "/activiti", "/logfile"};

        http.authorizeRequests().requestMatchers(adminEndpoints).permitAll()
                .and().authorizeRequests().anyRequest().authenticated();
    }

    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(username)
                .password(passwordEncoder().encode(password))
                .roles("USER");
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
