package com.tdei.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtValidationService {

    private final ApplicationProperties applicationProperties;
    private final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /**
     * Validates JWT token and extracts user information
     *
     * @param token The JWT token to validate
     * @return Client if token is valid
     */
    public Claims validateJwtToken(String token) {
        try {
            // Get key ID from header
            String[] parts = token.split("\\.");
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            Map<String, Object> header = objectMapper.readValue(headerJson, Map.class);
            String keyId = (String) header.get("kid");

            // Get or fetch public key
            PublicKey publicKey = publicKeyCache.computeIfAbsent(keyId, this::fetchPublicKey);
            if (publicKey == null) {
                throw new InvalidAccessTokenException("Unable to retrieve public key");
            }

            // Validate JWT
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims;

        } catch (Exception e) {
            log.error("JWT validation failed", e);
            throw new InvalidAccessTokenException("Invalid/Expired Access Token");
        }
    }

    /**
     * Fetches public key from JWKS endpoint
     */
    private PublicKey fetchPublicKey(String keyId) {
        try {
            String jwksUrl = applicationProperties.getKeycloak().getAuthServerUrl() + "/realms/"
                    + applicationProperties.getKeycloak().getRealm() + "/protocol/openid-connect/certs";
            HttpResponse<String> response = httpClient.send(
                    HttpRequest.newBuilder().uri(URI.create(jwksUrl)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());

            Map<String, Object> jwks = objectMapper.readValue(response.body(), Map.class);
            java.util.List<Object> keys = (java.util.List<Object>) jwks.get("keys");

            for (Object keyObj : keys) {
                Map<String, Object> key = (Map<String, Object>) keyObj;
                if (keyId.equals(key.get("kid"))) {
                    String n = (String) key.get("n");
                    String e = (String) key.get("e");
                    if (n != null && e != null) {
                        return createRSAPublicKey(n, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to fetch public key for kid: {}", keyId, e);
        }
        return null;
    }

    /**
     * Creates RSA public key from JWK components
     */
    private PublicKey createRSAPublicKey(String modulus, String exponent) throws Exception {
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new java.math.BigInteger(1, modulusBytes),
                new java.math.BigInteger(1, exponentBytes));
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
