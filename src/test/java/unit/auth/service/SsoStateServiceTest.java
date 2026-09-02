package unit.auth.service;

import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.JwtSigningKeyProvider;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.model.auth.dto.SsoStateContext;
import com.tdei.auth.service.SsoStateService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@Tag("Unit")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SsoStateServiceTest {

    private static final String REDIRECT_URI = "https://portal.tdei.us/login";
    private static final String CLIENT_ID = "tdei-portal";

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private JwtSigningKeyProvider jwtSigningKeyProvider;

    @Mock
    private ApplicationProperties.SsoProperties ssoProperties;

    @InjectMocks
    private SsoStateService ssoStateService;

    private SecretKey signingKey;

    @BeforeEach
    void setUp() {
        signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        when(jwtSigningKeyProvider.getSigningKey()).thenReturn(signingKey);
        when(jwtSigningKeyProvider.getSignatureAlgorithm()).thenReturn(SignatureAlgorithm.HS256);
    }

    private void stubSsoTtl() {
        when(applicationProperties.getSso()).thenReturn(ssoProperties);
        when(ssoProperties.getStateTtlSeconds()).thenReturn(600);
    }

    @Test
    @DisplayName("When creating SSO state, Expect signed JWT containing redirect_uri and client_id")
    void createStateTest() {
        stubSsoTtl();
        String state = ssoStateService.createState(REDIRECT_URI, CLIENT_ID);

        assertThat(state).isNotBlank();
        var claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(state)
                .getBody();
        assertThat(claims.get("redirect_uri", String.class)).isEqualTo(REDIRECT_URI);
        assertThat(claims.get("client_id", String.class)).isEqualTo(CLIENT_ID);
    }

    @Test
    @DisplayName("When validating valid SSO state, Expect redirect_uri and client_id returned")
    void validateStateTest() {
        stubSsoTtl();
        String state = ssoStateService.createState(REDIRECT_URI, CLIENT_ID);

        SsoStateContext context = ssoStateService.validateState(state);

        assertThat(context.getRedirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(context.getClientId()).isEqualTo(CLIENT_ID);
    }

    @Test
    @DisplayName("When validating expired SSO state, Expect InvalidCredentialsException")
    void validateExpiredStateTest() {
        String expiredState = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .claim("redirect_uri", REDIRECT_URI)
                .claim("client_id", CLIENT_ID)
                .setExpiration(Date.from(Instant.now().minus(1, ChronoUnit.MINUTES)))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(InvalidCredentialsException.class, () -> ssoStateService.validateState(expiredState));
    }

    @Test
    @DisplayName("When validating tampered SSO state, Expect InvalidCredentialsException")
    void validateTamperedStateTest() {
        SecretKey otherKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String tamperedState = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .claim("redirect_uri", REDIRECT_URI)
                .claim("client_id", CLIENT_ID)
                .setExpiration(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                .signWith(otherKey, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(InvalidCredentialsException.class, () -> ssoStateService.validateState(tamperedState));
    }
}
