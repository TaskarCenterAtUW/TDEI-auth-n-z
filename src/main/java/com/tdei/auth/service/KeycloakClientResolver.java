package com.tdei.auth.service;

import com.tdei.auth.core.config.TdeiKeycloakProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidSsoRequestException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KeycloakClientResolver {

    private final TdeiKeycloakProperties tdeiKeycloakProperties;

    public String resolveClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return getDefaultClientId();
        }
        validateClientId(clientId);
        return clientId;
    }

    public String getDefaultClientId() {
        String defaultClientId = tdeiKeycloakProperties.getDefaultClientId();
        if (defaultClientId == null || defaultClientId.isBlank()) {
            throw new IllegalStateException("tdei.keycloak.default-client-id is not configured");
        }
        validateClientId(defaultClientId);
        return defaultClientId;
    }

    public String getClientSecret(String clientId) {
        validateClientId(clientId);
        return tdeiKeycloakProperties.getClients().get(clientId);
    }

    public void validateClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new InvalidSsoRequestException("client_id is required");
        }
        var clients = tdeiKeycloakProperties.getClients();
        if (clients == null || !clients.containsKey(clientId)) {
            throw new InvalidSsoRequestException("Unknown client_id: " + clientId);
        }
        String secret = clients.get(clientId);
        if (secret == null || secret.isBlank()) {
            throw new InvalidSsoRequestException("Secret not configured for client_id: " + clientId);
        }
    }
}
