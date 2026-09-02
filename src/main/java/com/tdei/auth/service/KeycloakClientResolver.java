package com.tdei.auth.service;

import com.tdei.auth.core.config.TdeiKeycloakProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidSsoRequestException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

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
        return clients().get(clientId);
    }

    public void validateClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new InvalidSsoRequestException("client_id is required");
        }
        Map<String, String> clients = clients();
        if (clients.isEmpty()) {
            throw new IllegalStateException(
                    "tdei.keycloak.clients is empty. Set KEYCLOAK_AUTH_CLIENTS_CREDS "
                            + "(JSON {\"client-id\":\"secret\"} or client-id:secret;...). "
                            + "Raw value present=" + (tdeiKeycloakProperties.getClients() != null
                            && !tdeiKeycloakProperties.getClients().isBlank()));
        }
        if (!clients.containsKey(clientId)) {
            throw new InvalidSsoRequestException(
                    "Unknown client_id: " + clientId + ". Configured client ids: " + clients.keySet());
        }
        String secret = clients.get(clientId);
        if (secret == null || secret.isBlank()) {
            throw new InvalidSsoRequestException("Secret not configured for client_id: " + clientId);
        }
    }

    private Map<String, String> clients() {
        return tdeiKeycloakProperties.parsedClients();
    }
}
