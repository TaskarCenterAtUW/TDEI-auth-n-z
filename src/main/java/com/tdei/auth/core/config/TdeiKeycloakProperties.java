package com.tdei.auth.core.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "tdei.keycloak")
@Data
public class TdeiKeycloakProperties {
    private String defaultClientId;
    private Map<String, String> clients = new HashMap<>();
}
