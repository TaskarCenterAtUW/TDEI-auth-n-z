package com.tdei.auth.core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Client credentials must be bound as a {@link String}. Spring Boot treats {@code Map} properties
 * as nested key/value bindings and will not apply a String→Map converter for a single env var value.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "tdei.keycloak")
public class TdeiKeycloakProperties {
    private String defaultClientId;

    /**
     * Raw value from {@code TDEI_KEYCLOAK_CLIENTS}:
     * JSON {@code {"client-id":"secret"}} or delimited {@code client-id:secret|client-id2:secret2}.
     */
    private String clients;

    public Map<String, String> parsedClients() {
        return KeycloakClientsParser.parse(clients);
    }
}
