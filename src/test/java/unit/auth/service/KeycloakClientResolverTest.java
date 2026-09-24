package unit.auth.service;

import com.tdei.auth.core.config.TdeiKeycloakProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidSsoRequestException;
import com.tdei.auth.service.KeycloakClientResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("Unit")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KeycloakClientResolverTest {

    @Spy
    private TdeiKeycloakProperties tdeiKeycloakProperties = new TdeiKeycloakProperties();

    @InjectMocks
    private KeycloakClientResolver keycloakClientResolver;

    @BeforeEach
    void setUp() {
        tdeiKeycloakProperties.setDefaultClientId("tdei-gateway");
        tdeiKeycloakProperties.setClients("tdei-gateway:gateway-secret;tdei-portal:portal-secret");
    }

    @Test
    @DisplayName("When client_id is omitted, Expect default client id returned")
    void resolveClientIdDefaultsToAdminTest() {
        assertEquals("tdei-gateway", keycloakClientResolver.resolveClientId(null));
        assertEquals("tdei-gateway", keycloakClientResolver.resolveClientId(""));
    }

    @Test
    @DisplayName("When client_id is provided, Expect same client id returned")
    void resolveClientIdProvidedTest() {
        assertEquals("tdei-portal", keycloakClientResolver.resolveClientId("tdei-portal"));
    }

    @Test
    @DisplayName("When client_id is configured, Expect secret returned")
    void getClientSecretTest() {
        assertEquals("portal-secret", keycloakClientResolver.getClientSecret("tdei-portal"));
    }

    @Test
    @DisplayName("When client_id is unknown, Expect InvalidSsoRequestException")
    void unknownClientTest() {
        assertThrows(InvalidSsoRequestException.class, () -> keycloakClientResolver.validateClientId("unknown"));
    }

    @Test
    @DisplayName("When default client is configured, Expect default client id returned")
    void getDefaultClientIdTest() {
        assertEquals("tdei-gateway", keycloakClientResolver.getDefaultClientId());
        assertDoesNotThrow(() -> keycloakClientResolver.getClientSecret("tdei-gateway"));
    }

    @Test
    @DisplayName("When clients env is empty, Expect IllegalStateException mentioning TDEI_KEYCLOAK_CLIENTS")
    void emptyClientsTest() {
        tdeiKeycloakProperties.setClients("");
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> keycloakClientResolver.validateClientId("tdei-gateway"));
        assertEquals(true, ex.getMessage().contains("TDEI_KEYCLOAK_CLIENTS"));
    }
}
