package com.tdei.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeRequests()
                //.antMatchers(HttpMethod.POST, "/api/v1.0/private/gtfs-flex").hasAnyAuthority("publisher")
                //.antMatchers(HttpMethod.GET, "/api/v1/agencies").hasAnyAuthority("app-user")
                //.antMatchers("/*").
                .anyRequest().
                permitAll();
        return http.build();
    }
}
