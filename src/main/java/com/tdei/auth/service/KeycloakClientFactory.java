package com.tdei.auth.service;

import com.tdei.auth.core.config.ApplicationProperties;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Component;

@Component
public class KeycloakClientFactory {

    private final ApplicationProperties applicationProperties;
    private final KeycloakClientResolver keycloakClientResolver;

    public KeycloakClientFactory(ApplicationProperties applicationProperties,
                                 KeycloakClientResolver keycloakClientResolver) {
        this.applicationProperties = applicationProperties;
        this.keycloakClientResolver = keycloakClientResolver;
    }

    public Keycloak buildClientCredentialsClient(String clientId) {
        String resolvedClientId = keycloakClientResolver.resolveClientId(clientId);
        return KeycloakBuilder.builder()
                .serverUrl(applicationProperties.getKeycloak().getAuthServerUrl())
                .realm(applicationProperties.getKeycloak().getRealm())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(resolvedClientId)
                .clientSecret(keycloakClientResolver.getClientSecret(resolvedClientId))
                .resteasyClient(buildResteasyClient())
                .build();
    }

    public Keycloak buildPasswordGrantClient(String clientId, String username, String password) {
        String resolvedClientId = keycloakClientResolver.resolveClientId(clientId);
        return KeycloakBuilder.builder()
                .serverUrl(applicationProperties.getKeycloak().getAuthServerUrl())
                .realm(applicationProperties.getKeycloak().getRealm())
                .grantType(OAuth2Constants.PASSWORD)
                .clientId(resolvedClientId)
                .clientSecret(keycloakClientResolver.getClientSecret(resolvedClientId))
                .username(username)
                .password(password)
                .resteasyClient(buildResteasyClient())
                .build();
    }

    public Keycloak buildAppClientCredentialsClient(String clientId, String clientSecret) {
        return KeycloakBuilder.builder()
                .serverUrl(applicationProperties.getKeycloak().getAuthServerUrl())
                .realm(applicationProperties.getKeycloak().getRealm())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

    private org.jboss.resteasy.client.jaxrs.ResteasyClient buildResteasyClient() {
        return new ResteasyClientBuilder()
                .connectionPoolSize(applicationProperties.getKeycloak().getConnectionPoolSize())
                .connectTimeout(applicationProperties.getKeycloak().getConnectionTimeout(), TimeUnit.SECONDS)
                .build();
    }
}
