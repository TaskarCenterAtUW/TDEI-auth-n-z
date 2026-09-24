package com.tdei.auth.core.config;

import com.tdei.auth.service.KeycloakClientFactory;
import org.keycloak.admin.client.Keycloak;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BeanConfig {

    private final KeycloakClientFactory keycloakClientFactory;

    public BeanConfig(KeycloakClientFactory keycloakClientFactory) {
        this.keycloakClientFactory = keycloakClientFactory;
    }

    @Bean
    public Keycloak keycloakInstance() {
        return keycloakClientFactory.buildClientCredentialsClient(null);
    }
}
