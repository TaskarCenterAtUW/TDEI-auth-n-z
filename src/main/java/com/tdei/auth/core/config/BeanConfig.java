package com.tdei.auth.core.config;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class BeanConfig {

    @Autowired
    ApplicationProperties applicationProperties;

    @Bean
    public Keycloak keycloakInstance() {
        var keycloak = KeycloakBuilder.builder()
                .serverUrl(applicationProperties.getKeycloak().getAuthServerUrl())
                .realm(applicationProperties.getKeycloak().getRealm())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(applicationProperties.getKeycloak().getResource())
                .clientSecret(applicationProperties.getKeycloak().getCredentials().getSecret())
                .resteasyClient(new ResteasyClientBuilder()
                        .connectionPoolSize(applicationProperties.getKeycloak().getConnectionPoolSize())
                        .connectTimeout(applicationProperties.getKeycloak().getConnectionTimeout(), TimeUnit.SECONDS)
                        .build()
                )
                .build();

        return keycloak;
    }
}
