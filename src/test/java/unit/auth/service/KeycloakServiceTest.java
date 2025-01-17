package unit.auth.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.core.config.exception.handler.exceptions.UserExistsException;
import com.tdei.auth.model.auth.dto.RegisterUser;
import com.tdei.auth.model.auth.dto.UserRoles;
import com.tdei.auth.repository.UserManagementRepository;
import com.tdei.auth.service.KeycloakService;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;

@Tag("Unit")
@ExtendWith(MockitoExtension.class)
public class KeycloakServiceTest {
    private static WireMockServer wireMockServer;
    private static int TEST_PORT = 8650;
    @Spy
    UsersResource usersResourceSpy;
    @Spy
    RealmResource realmResourceSpy;
    @Mock
    private Keycloak keycloakInstance;
    @Mock
    private KeycloakBuilder keycloakBuilder;
    @Mock
    private ApplicationProperties applicationProperties;
    @Mock
    private UserManagementRepository userManagementRepository;
    @Mock
    private ApplicationProperties.keycloakProperties keycloakProperties;
    @InjectMocks
    private KeycloakService keycloakService;

    @BeforeAll
    static void init() {
        wireMockServer = new WireMockServer(
                new WireMockConfiguration().port(TEST_PORT)
        );
        wireMockServer.start();
        WireMock.configureFor("localhost", TEST_PORT);
    }

    private static UserRoles getUserRoles(String roleName) {
        var flexDataRole = new UserRoles();
        flexDataRole.setRoleName(roleName);
        flexDataRole.setUserId("test_user_id");
        flexDataRole.setProjectGroupId("test_project_group_id");
        return flexDataRole;
    }

    private UsersResource mockUserInstance() {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getRealm()).thenReturn("test realm");
        when(keycloakInstance.realm(any())).thenReturn(realmResourceSpy);
        when(realmResourceSpy.users()).thenReturn(usersResourceSpy);
        return usersResourceSpy;
    }

    @Test
    @DisplayName("When searching for user by valid api-key, Expect to return User details")
    void getUserByApiKeyTest() throws InvalidKeyException {
        //Arrange
        UsersResource usersResourceSpy = mockUserInstance();
        when(usersResourceSpy.searchByAttributes(any())).thenReturn(Arrays.asList(new UserRepresentation()));
        //Act
        var user = keycloakService.getUserByApiKey("test_key");

        //Assert
        assertThat(user != null);
    }

    @Test()
    @DisplayName("When searching for user by invalid api-key, Expect to throw InvalidKeyException")
    void getUserByApiKeyTest2() {
        //Arrange
        UsersResource usersResourceSpy = mockUserInstance();
        when(usersResourceSpy.searchByAttributes(any())).thenReturn(Arrays.asList());

        //Act & Assert
        assertThrows(InvalidKeyException.class, () -> keycloakService.getUserByApiKey("test_key"));
    }

    @Test()
    @DisplayName("When searching for user by valid access token, Expect to return userinfo")
    void getUserByAccessTokenTest() {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getResource()).thenReturn("test");
        var mockCred = mock(ApplicationProperties.keycloakProperties.KeycloakCreds.class);
        when(keycloakProperties.getCredentials()).thenReturn(mockCred);
        when(mockCred.getSecret()).thenReturn("test_secret");
        var mockEndpointUrls = mock(ApplicationProperties.KeycloakEndpointUrls.class);
        when(applicationProperties.getKeycloakClientEndpoints()).thenReturn(mockEndpointUrls);
        when(mockEndpointUrls.getBaseUrl()).thenReturn("http://localhost:" + TEST_PORT);
        stubFor(WireMock.post(urlMatching("/userinfo/"))
                .willReturn(aResponse()
                        .withBody("{\n" +
                                "    \"sub\": \"ed291f7a-a799-4d8b-a776-e634d727668c\",\n" +
                                "    \"email_verified\": true,\n" +
                                "    \"preferred_username\": \"admin\"\n" +
                                "}")
                        .withHeader("Content-Type", String.valueOf(equalTo("application/json")))
                        .withStatus(OK.value())));
        //Act & Assert
        assertThat(keycloakService.getUserByAccessToken("test_access_token").get().getPreferred_username().equals("admin"));
    }

    @Test()
    @DisplayName("When searching for user by invalid access token, Expect to throw InvalidAccessTokenException")
    void getUserByAccessTokenTest2() {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getResource()).thenReturn("test");
        var mockCred = mock(ApplicationProperties.keycloakProperties.KeycloakCreds.class);
        when(keycloakProperties.getCredentials()).thenReturn(mockCred);
        when(mockCred.getSecret()).thenReturn("test_secret");
        var mockEndpointUrls = mock(ApplicationProperties.KeycloakEndpointUrls.class);
        when(applicationProperties.getKeycloakClientEndpoints()).thenReturn(mockEndpointUrls);
        when(mockEndpointUrls.getBaseUrl()).thenReturn("http://localhost:" + TEST_PORT);
        stubFor(WireMock.post(urlMatching("/userinfo/"))
                .willReturn(aResponse()
                        .withStatus(NOT_FOUND.value())));

        //Act & Assert
        assertThrows(InvalidAccessTokenException.class, () -> keycloakService.getUserByAccessToken("test_access_token"));
    }

    @Test
    @DisplayName("When searching for the user by valid user name, Expect to return userinfo")
    void getUserByUserNameTest() throws Exception {
        //Arrange
        UsersResource usersResourceSpy = mockUserInstance();
        var userResponse = new UserRepresentation();
        userResponse.setEmail("test@email.com");
        var attributes = new HashMap();
        attributes.put("phone", Arrays.asList("9999999999"));
        attributes.put("x-api-key", Arrays.asList("test-x-api-key"));
        userResponse.setAttributes(attributes);
        when(usersResourceSpy.search(anyString(), anyBoolean())).thenReturn(Arrays.asList(userResponse));

        //Act
        var user = keycloakService.getUserByUserName("test_username");

        //Assert
        assertThat(user.getEmail().equals(userResponse.getEmail()));
    }

    @Test
    @DisplayName("When searching for the user by invalid user name, Expect to return null")
    void getUserByUserNameTest2() throws Exception {
        //Arrange
        UsersResource usersResourceSpy = mockUserInstance();
        when(usersResourceSpy.search(anyString(), anyBoolean())).thenReturn(Arrays.asList());

        //Act
        var user = keycloakService.getUserByUserName("test_username_invalid");

        //Assert
        assertThat(user).isNull();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid , projectGroupId and roles, Expect to return true")
    void hasPermissionTest() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.of("test_project_group_id"), new String[]{"flex_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isTrue();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, role and invalid projectGroupId, Expect to return false")
    void hasPermissionTest2() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.of("test_project_group_id_2"), new String[]{"flex_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isFalse();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, role and empty projectGroupId, Expect to return true")
    void hasPermissionTest3() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.empty(), new String[]{"flex_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isTrue();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, projectGroupId and invalid roles, Expect to return false")
    void hasPermissionTest4() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.of("test_project_group_id"), new String[]{"pathways_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isFalse();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, empty projectGroupId and invalid roles, Expect to return false")
    void hasPermissionTest5() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.empty(), new String[]{"pathways_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isFalse();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, projectGroupId , must exists roles and on partial role match, Expect to return false")
    void hasPermissionTest6() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.of("test_project_group_id"), new String[]{"flex_data_generator", "pathways_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isFalse();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, projectGroupId , must exists roles and on partial role match, Expect to return true when affirmative flag is false")
    void hasPermissionTest8() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.of("test_project_group_id"), new String[]{"flex_data_generator", "pathways_data_generator"}, Optional.of(false));

        //Assert
        assertThat(satisfied).isTrue();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, empty projectGroupId , must exists roles and on partial role match, Expect to return false")
    void hasPermissionTest7() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.empty(), new String[]{"flex_data_generator", "pathways_data_generator"}, Optional.of(true));

        //Assert
        assertThat(satisfied).isFalse();
    }

    @Test
    @DisplayName("When validating user permissions with valid userid, empty projectGroupId , must exists roles and on partial role match, Expect to return true when affirmative flag is false")
    void hasPermissionTest9() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("flex_data_generator");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.empty(), new String[]{"flex_data_generator", "pathways_data_generator"}, Optional.of(false));

        //Assert
        assertThat(satisfied).isTrue();
    }

    @Test
    @DisplayName("When validating user permissions where user is admin, Expect to return true")
    void hasPermissionTest10() {
        //Arrange
        MockitoAnnotations.openMocks(this);
        UserRoles flexDataRole = getUserRoles("tdei_admin");
        when(userManagementRepository.getUserRoles(ArgumentMatchers.anyString())).thenReturn(Arrays.asList(flexDataRole));

        //Act
        var satisfied = keycloakService.hasPermission("test_user_id", Optional.empty(), new String[]{"flex_data_generator", "pathways_data_generator"}, Optional.of(false));

        //Assert
        assertThat(satisfied).isTrue();
    }

    @Test
    @DisplayName("When registering new user , Expect to return userprofile on success")
    void registerUserTest() throws Exception {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getResource()).thenReturn("test");
        when(applicationProperties.getKeycloakClientEndpoints()).thenReturn(new ApplicationProperties.KeycloakEndpointUrls());
        var registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("FName");
        registerUser.setLastName("LName");
        registerUser.setPassword("Password");
        registerUser.setPhone("9999999999");

        var userRepresentation = new UserRepresentation();
        userRepresentation.setEmail("test@email.com");
        userRepresentation.setFirstName("FName");
        userRepresentation.setLastName("LName");
        var attributes = new HashMap();
        attributes.put("phone", Arrays.asList("9999999999"));
        attributes.put("x-api-key", Arrays.asList("test-x-api-key"));
        userRepresentation.setAttributes(attributes);

        mockUserInstance();

        var responseMock = mock(Response.class);
        when(responseMock.getStatus()).thenReturn(201);
        when(responseMock.getLocation()).thenReturn(new URI("http://localhost:" + TEST_PORT + "/new_user_id"));
        when(usersResourceSpy.create(any(UserRepresentation.class))).thenReturn(responseMock);

        var usersResourceInlineMock = mock(UserResource.class);
        when(usersResourceSpy.get(anyString())).thenReturn(usersResourceInlineMock);
        when((usersResourceInlineMock).toRepresentation()).thenReturn(userRepresentation);

        //Act
        var userProfile = keycloakService.registerUser(registerUser);
        //Assert
        assertThat(userProfile.getEmail()).isEqualTo(registerUser.getEmail());
    }

    @Test
    @DisplayName("When registering new user with existing user email , Expect to throw UserExistsException")
    void registerUserTest2() {
        //Arrange
        var registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("FName");
        registerUser.setLastName("LName");
        registerUser.setPassword("Password");
        registerUser.setPhone("9999999999");

        var userRepresentation = new UserRepresentation();
        userRepresentation.setEmail("test@email.com");
        userRepresentation.setFirstName("FName");
        userRepresentation.setLastName("LName");
        var attributes = new HashMap();
        attributes.put("phone", Arrays.asList("9999999999"));
        attributes.put("x-api-key", Arrays.asList("test-x-api-key"));
        userRepresentation.setAttributes(attributes);

        mockUserInstance();

        var responseMock = mock(Response.class);
        when(responseMock.getStatus()).thenReturn(409);
        when(usersResourceSpy.create(any(UserRepresentation.class))).thenReturn(responseMock);

        //Act & Assert
        assertThrows(UserExistsException.class, () -> keycloakService.registerUser(registerUser));
    }

    @Test()
    @DisplayName("When requested to re-issue token given valid refresh token, Expect to return TokenResponse on success")
    void reIssueToken() {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getResource()).thenReturn("test");
        var mockCred = mock(ApplicationProperties.keycloakProperties.KeycloakCreds.class);
        when(keycloakProperties.getCredentials()).thenReturn(mockCred);
        when(mockCred.getSecret()).thenReturn("test_secret");
        var mockEndpointUrls = mock(ApplicationProperties.KeycloakEndpointUrls.class);
        when(applicationProperties.getKeycloakClientEndpoints()).thenReturn(mockEndpointUrls);
        when(mockEndpointUrls.getBaseUrl()).thenReturn("http://localhost:" + TEST_PORT);

        stubFor(WireMock.post(urlMatching("/token/"))
                .willReturn(aResponse()
                        .withBody("{\n" +
                                "    \"access_token\": \"ed291f7a-a799-4d8b-a776-e634d727668c\",\n" +
                                "    \"refresh_token\": \"ed291f7a-a799-4d8b-a776-e634d727668c\",\n" +
                                "    \"expires_in\": 1234,\n" +
                                "    \"refresh_expires_in\": 1234\n" +
                                "}")
                        .withHeader("Content-Type", String.valueOf(equalTo("application/json")))
                        .withStatus(OK.value())));

        //Act
        var result = keycloakService.reIssueToken("valid_refresh_token");

        //Assert
        assertThat(result).isNotNull();
    }

    @Test()
    @DisplayName("When requested to re-issue token given expired refresh token, Expect to throw InvalidAccessTokenException")
    void reIssueToken2() {
        //Arrange
        when(applicationProperties.getKeycloak()).thenReturn(keycloakProperties);
        when(keycloakProperties.getResource()).thenReturn("test");
        var mockCred = mock(ApplicationProperties.keycloakProperties.KeycloakCreds.class);
        when(keycloakProperties.getCredentials()).thenReturn(mockCred);
        when(mockCred.getSecret()).thenReturn("test_secret");
        var mockEndpointUrls = mock(ApplicationProperties.KeycloakEndpointUrls.class);
        when(applicationProperties.getKeycloakClientEndpoints()).thenReturn(mockEndpointUrls);
        when(mockEndpointUrls.getBaseUrl()).thenReturn("http://localhost:" + TEST_PORT);

        stubFor(WireMock.post(urlMatching("/token/"))
                .willReturn(aResponse()
                        .withBody("{\n" +
                                "    \"access_token\": \"ed291f7a-a799-4d8b-a776-e634d727668c\",\n" +
                                "    \"refresh_token\": \"ed291f7a-a799-4d8b-a776-e634d727668c\",\n" +
                                "    \"expires_in\": 1234,\n" +
                                "    \"refresh_expires_in\": 1234\n" +
                                "}")
                        .withHeader("Content-Type", String.valueOf(equalTo("application/json")))
                        .withStatus(NOT_FOUND.value())));

        //Act & Assert
        assertThrows(InvalidAccessTokenException.class, () -> keycloakService.reIssueToken("expired_refresh_token"));
    }


    @Test()
    @DisplayName("When requested to generate secret token, Expect to return secret token")
    void generateSecretTest() {
        //Arrange
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String secretString = Encoders.BASE64.encode(key.getEncoded());
        var springPropertiesMock = mock(ApplicationProperties.SpringProperties.class);
        var springPropertiesApplicationMock = mock(ApplicationProperties.SpringProperties.Application.class);
        when(applicationProperties.getSpring()).thenReturn(springPropertiesMock);
        when(springPropertiesMock.getApplication()).thenReturn(springPropertiesApplicationMock);
        when(springPropertiesApplicationMock.getSecretTtl()).thenReturn(1234);
        when(springPropertiesApplicationMock.getSecret()).thenReturn(secretString);

        //Act
        var result = keycloakService.generateSecret();

        //Assert
        assertThat(result).isNotBlank();
    }

    @Test()
    @DisplayName("When requested to validate secret token, Expect to return true on success")
    void validateSecret() {
        //Arrange
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String secretString = Encoders.BASE64.encode(key.getEncoded());

        var springPropertiesMock = mock(ApplicationProperties.SpringProperties.class);
        var springPropertiesApplicationMock = mock(ApplicationProperties.SpringProperties.Application.class);
        when(applicationProperties.getSpring()).thenReturn(springPropertiesMock);
        when(springPropertiesMock.getApplication()).thenReturn(springPropertiesApplicationMock);
        when(springPropertiesApplicationMock.getSecretTtl()).thenReturn(1234);
        when(springPropertiesApplicationMock.getSecret()).thenReturn(secretString);

        //Act
        var secretToken = keycloakService.generateSecret();
        var result = keycloakService.validateSecret(secretToken);
        //Assert
        assertThat(result).isTrue();
    }

    @Test()
    @DisplayName("When requested to validate invalid secret token, Expect to return false")
    void validateSecret2() {
        //Arrange
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String secretString = Encoders.BASE64.encode(key.getEncoded());

        var springPropertiesMock = mock(ApplicationProperties.SpringProperties.class);
        var springPropertiesApplicationMock = mock(ApplicationProperties.SpringProperties.Application.class);
        when(applicationProperties.getSpring()).thenReturn(springPropertiesMock);
        when(springPropertiesMock.getApplication()).thenReturn(springPropertiesApplicationMock);
        when(springPropertiesApplicationMock.getSecret()).thenReturn(secretString);

        //Act
        var result = keycloakService.validateSecret("invalid_secretToken");
        //Assert
        assertThat(result).isFalse();
    }

}
