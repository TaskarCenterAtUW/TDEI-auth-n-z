package com.tdei.auth.core.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

public final class KeycloakClientsParser {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private KeycloakClientsParser() {
    }

    public static Map<String, String> parse(String source) {
        if (source == null || source.isBlank()) {
            return new HashMap<>();
        }

        String trimmed = unwrapQuotes(source.trim());
        if (trimmed.isBlank()) {
            return new HashMap<>();
        }
        if (trimmed.startsWith("{")) {
            return parseJson(trimmed);
        }
        return parseDelimited(trimmed);
    }

    /** Strip wrapping single/double quotes Azure or shells sometimes add around the whole value. */
    private static String unwrapQuotes(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '\'' && last == '\'') || (first == '"' && last == '"')) {
                return value.substring(1, value.length() - 1).trim();
            }
        }
        return value;
    }

    private static Map<String, String> parseJson(String json) {
        try {
            Map<String, String> clients = OBJECT_MAPPER.readValue(json, new TypeReference<Map<String, String>>() {});
            return clients != null ? clients : new HashMap<>();
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Invalid KEYCLOAK_AUTH_CLIENTS_CREDS JSON. Expected format: {\"client-id\":\"secret\"}", e);
        }
    }

    private static Map<String, String> parseDelimited(String source) {
        Map<String, String> clients = new HashMap<>();
        for (String entry : source.split(";")) {
            if (entry.isBlank()) {
                continue;
            }
            int separator = entry.indexOf(':');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw new IllegalArgumentException(
                        "Invalid KEYCLOAK_AUTH_CLIENTS_CREDS entry '" + entry + "'. Expected client-id:secret");
            }
            String clientId = entry.substring(0, separator).trim();
            String secret = entry.substring(separator + 1).trim();
            if (clientId.isEmpty() || secret.isEmpty()) {
                throw new IllegalArgumentException(
                        "Invalid KEYCLOAK_AUTH_CLIENTS_CREDS entry '" + entry + "'. Expected client-id:secret");
            }
            clients.put(clientId, secret);
        }
        return clients;
    }
}
