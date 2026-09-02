package com.tdei.auth.service;

import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.JwtSigningKeyProvider;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.model.auth.dto.SsoStateContext;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class SsoStateService {

    private static final String REDIRECT_URI_CLAIM = "redirect_uri";
    private static final String CLIENT_ID_CLAIM = "client_id";

    private final ApplicationProperties applicationProperties;
    private final JwtSigningKeyProvider jwtSigningKeyProvider;

    public String createState(String redirectUri, String clientId) {
        int ttlSeconds = applicationProperties.getSso().getStateTtlSeconds();
        Date expiration = Date.from(Instant.now().plus(ttlSeconds, ChronoUnit.SECONDS));

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .claim(REDIRECT_URI_CLAIM, redirectUri)
                .claim(CLIENT_ID_CLAIM, clientId)
                .setExpiration(expiration)
                .signWith(jwtSigningKeyProvider.getSigningKey(), jwtSigningKeyProvider.getSignatureAlgorithm())
                .compact();
    }

    public SsoStateContext validateState(String state) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtSigningKeyProvider.getSigningKey())
                    .build()
                    .parseClaimsJws(state)
                    .getBody();

            String redirectUri = claims.get(REDIRECT_URI_CLAIM, String.class);
            String clientId = claims.get(CLIENT_ID_CLAIM, String.class);
            if (redirectUri == null || redirectUri.isBlank() || clientId == null || clientId.isBlank()) {
                throw new InvalidCredentialsException("Invalid SSO state");
            }
            return new SsoStateContext(redirectUri, clientId);
        } catch (ExpiredJwtException e) {
            log.error("SSO state expired", e);
            throw new InvalidCredentialsException("Invalid or expired SSO state");
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            log.error("SSO state validation failed", e);
            throw new InvalidCredentialsException("Invalid or expired SSO state");
        }
    }
}
