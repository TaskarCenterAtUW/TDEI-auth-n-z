package unit.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tdei.auth.controller.authentication.Authentication;
import com.tdei.auth.core.config.exception.handler.exceptions.*;
import com.tdei.auth.model.auth.dto.*;
import com.tdei.auth.model.common.dto.LoginModel;
import com.tdei.auth.model.common.dto.ResetCredentialModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.service.KeycloakClientResolver;
import com.tdei.auth.service.KeycloakService;
import com.tdei.auth.service.SsoRedirectValidator;
import com.tdei.auth.service.SsoStateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.security.InvalidKeyException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@Tag("Unit")
@ExtendWith(MockitoExtension.class)
public class authControllerTest {
    @Mock
    private KeycloakService keycloakService;
    @Mock
    private SsoStateService ssoStateService;
    @Mock
    private SsoRedirectValidator ssoRedirectValidator;
    @Mock
    private KeycloakClientResolver keycloakClientResolver;
    @InjectMocks
    private Authentication authController;
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private Validator validator;

    @BeforeEach
    public void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    @DisplayName("When validating the valid API key, Expect to return HTTP Status 200 with user profile details")
    void validateApiKeyTest() throws InvalidKeyException {

        when(keycloakService.getUserByApiKey("test_api_key")).thenReturn(Optional.of(new UserRepresentation()));
        var user = authController.validateApiKey("test_api_key");
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(UserProfile.class);
    }

    @Test
    @DisplayName("When validating the invalid API key, Expect to throw InvalidKeyException")
    void validateApiKeyTest2() throws InvalidKeyException {
        //Arrange
        when(keycloakService.getUserByApiKey("test_api_key")).thenThrow(new InvalidKeyException("Invalid API Key exception"));
        //Act & Arrange
        assertThrows(InvalidKeyException.class, () -> authController.validateApiKey("test_api_key"));
    }

    @Test
    @DisplayName("When validating the valid Access Token, Expect to return HTTP Status 200 with user profile details")
    void validateAccessTokenTest() {
        //Arrange
        when(keycloakService.getUserByAccessToken("test_access_token")).thenReturn(Optional.of(new KUserInfo()));

        //Act
        var user = authController.validateAccessToken("test_access_token");

        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(UserProfile.class);
    }

    @Test
    @DisplayName("When validating the invalid Access Token, Expect to throw InvalidAccessTokenException")
    void validateAccessTokenTest2() {
        //Arrange
        when(keycloakService.getUserByAccessToken("test_access_token")).thenThrow(new InvalidAccessTokenException("Invalid/Expired Access Token"));
        //Act & Arrange
        assertThrows(InvalidAccessTokenException.class, () -> authController.validateAccessToken("test_access_token"));
    }

    @Test
    @DisplayName("When authenticating user with valid credentials, Expect to return HTTP Status 200 with TokenResponse details")
    void authenticateTest() throws TimeoutException {
        //Arrange
        LoginModel loginModel = new LoginModel();
        loginModel.setUsername("test_username");
        loginModel.setPassword("test_password");
        when(keycloakService.getUserToken(loginModel)).thenReturn(new AccessTokenResponse());

        //Act
        var user = authController.authenticate(loginModel);
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(TokenResponse.class);
    }

    @Test
    @DisplayName("When validating the LoginModel with password policy not satisfied, Expect to return error")
    public void testInvalidLoginModel() {
        LoginModel loginModel = new LoginModel();
        loginModel.setUsername("user@tdei.com"); // Invalid username
        loginModel.setPassword("test"); // Invalid password

        Set<ConstraintViolation<LoginModel>> violations = validator.validate(loginModel);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the LoginModel with password > 255, Expect to return error")
    public void testLongPasswordLoginModel() {
        LoginModel loginModel = new LoginModel();
        loginModel.setUsername("user@tdei.com"); // Invalid username
        loginModel.setPassword("ABCD*EFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567HIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); // Invalid password

        Set<ConstraintViolation<LoginModel>> violations = validator.validate(loginModel);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When authenticating user with invalid credentials, Expect to throw InvalidCredentialsException")
    void authenticateTest2() throws TimeoutException {
        //Arrange
        LoginModel loginModel = new LoginModel();
        loginModel.setUsername("test_username");
        loginModel.setPassword("test_password");

        //Act
        when(keycloakService.getUserToken(loginModel)).thenThrow(new InvalidCredentialsException("Invalid Credentials"));
        //Act & Arrange
        assertThrows(InvalidCredentialsException.class, () -> authController.authenticate(loginModel));
    }

    @Test
    @DisplayName("When verifying the user permission with valid userid, projectGroupId and matching roles, Expect to return true")
    void hasPermissionTest() {
        //Arrange
        when(keycloakService.hasPermission("userId", Optional.of("projectGroupId"), new String[]{"flex_data_generator"}, Optional.of(true))).thenReturn(true);

        //Act
        var user = authController.hasPermission("userId", Optional.of("projectGroupId"), new String[]{"flex_data_generator"}, Optional.of(true));
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isTrue();
    }

    @Test
    @DisplayName("When verifying the user permission with valid userid, projectGroupId and not matching roles, Expect to return false")
    void hasPermissionTest2() {
        //Arrange
        when(keycloakService.hasPermission("userId", Optional.of("projectGroupId"), new String[]{"flex_data_generator"}, Optional.of(true))).thenReturn(false);

        //Act
        var user = authController.hasPermission("userId", Optional.of("projectGroupId"), new String[]{"flex_data_generator"}, Optional.of(true));
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isFalse();
    }

    @Test
    @DisplayName("When refreshing the valid refresh token, Expect to return TokenResponse")
    void reIssueTokenTest() {
        //Arrange
        var request = new RefreshTokenRequest();
        request.setRefreshToken("refresh_token");
        request.setClientId("tdei-gateway");
        when(keycloakClientResolver.resolveClientId("tdei-gateway")).thenReturn("tdei-gateway");
        when(keycloakService.reIssueToken("refresh_token", "tdei-gateway")).thenReturn(new TokenResponse());

        //Act
        var user = authController.reIssueToken(request);
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(TokenResponse.class);
    }

    @Test
    @DisplayName("When refreshing the invalid refresh token, Expect to throw InvalidAccessTokenException")
    void reIssueTokenTest2() {
        //Arrange
        var request = new RefreshTokenRequest();
        request.setRefreshToken("refresh_token");
        request.setClientId("tdei-gateway");
        when(keycloakClientResolver.resolveClientId("tdei-gateway")).thenReturn("tdei-gateway");
        when(keycloakService.reIssueToken("refresh_token", "tdei-gateway")).thenThrow(new InvalidAccessTokenException("Invalid/Expired Access Token"));
        //Act & Arrange
        assertThrows(InvalidAccessTokenException.class, () -> authController.reIssueToken(request));
    }

    @Test
    @DisplayName("When requested to generate secret token, Expect to return secret token")
    void generateSecretTest() {
        //Arrange
        when(keycloakService.generateSecret()).thenReturn("new secret token");

        //Act
        var user = authController.generateSecret();
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isNotBlank();
    }

    @Test
    @DisplayName("When requested to validate secret token, Expect to return true on success")
    void validateSecretTest() {
        //Arrange
        when(keycloakService.validateSecret("secret_token")).thenReturn(true);

        //Act
        var user = authController.validateSecret("secret_token");
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isEqualTo("true");
    }

    @Test
    @DisplayName("When requested to register new user, Expect to return UserProfile on success")
    void registerUserTest() throws Exception {
        //Arrange
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("firstname");
        registerUser.setLastName("lastname");
        registerUser.setPhone("phone");
        registerUser.setPassword("password");

        when(keycloakService.registerUser(registerUser)).thenReturn(new UserProfile());

        //Act
        var user = authController.registerUser(registerUser);
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(UserProfile.class);
    }

    @Test
    @DisplayName("When requested to register new user with promo code, Expect to return UserProfile on success")
    void registerUserWithPromoTest() throws Exception {
        //Arrange
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("firstname");
        registerUser.setLastName("lastname");
        registerUser.setPhone("phone");
        registerUser.setPassword("password");
        registerUser.setCode("PROMO2024");

        when(keycloakService.registerUser(registerUser)).thenReturn(new UserProfile());

        //Act
        var user = authController.registerUser(registerUser);
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(UserProfile.class);
    }

    @Test
    @DisplayName("When requested to register new user with existing email, Expect to throw UserExistsException")
    void registerUserTest2() throws Exception {
        //Arrange
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("firstname");
        registerUser.setLastName("lastname");
        registerUser.setPhone("phone");
        registerUser.setPassword("password");

        when(keycloakService.registerUser(registerUser)).thenThrow(new UserExistsException("test@email.com"));

        //Act & Arrange
        assertThrows(UserExistsException.class, () -> authController.registerUser(registerUser));
    }

    @Test
    @DisplayName("When requested get user details by username, Expect to return UserProfile details on success")
    void getUserByUserNameTest() throws Exception {
        //Arrange
        when(keycloakService.getUserByUserName("user_name")).thenReturn(new UserProfile());

        //Act
        var user = authController.getUserByUserName("user_name");
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).isInstanceOf(UserProfile.class);
    }

    @Test
    @DisplayName("When requested get user details by invalid username, Expect to return HTTP Status 404")
    void getUserByUserNameTest2() throws Exception {
        //Arrange
        when(keycloakService.getUserByUserName("user_name")).thenReturn(null);

        //Act
        var user = authController.getUserByUserName("user_name");
        //Assert
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("When resetting credentials with valid request, Expect to return true")
    void shouldResetCredentialsWithValidRequest() throws Exception {
        ResetCredentialModel resetCredentialModel = new ResetCredentialModel();
        resetCredentialModel.setUsername("testUserId");
        resetCredentialModel.setPassword("testPassword");
        when(keycloakService.resetCredentials(resetCredentialModel)).thenReturn(true);
        ResponseEntity<Boolean> response = authController.resetCredentials(resetCredentialModel);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody());
    }

    @Test
    @DisplayName("When resetting credentials with non-existing user, Expect to throw ResourceNotFoundException")
    void shouldThrowResourceNotFoundExceptionWhenUserDoesNotExist() throws Exception {
        ResetCredentialModel resetCredentialModel = new ResetCredentialModel();
        resetCredentialModel.setUsername("nonExistingUserId");
        resetCredentialModel.setPassword("testPassword");
        when(keycloakService.resetCredentials(resetCredentialModel)).thenThrow(new ResourceNotFoundException("User not found"));
        assertThrows(ResourceNotFoundException.class, () -> authController.resetCredentials(resetCredentialModel));
    }

    @Test
    @DisplayName("When resetting credentials and an error occurs, Expect to throw Exception")
    void shouldThrowExceptionWhenErrorOccurs() throws Exception {
        ResetCredentialModel resetCredentialModel = new ResetCredentialModel();
        resetCredentialModel.setUsername("testUserId");
        resetCredentialModel.setPassword("testPassword");
        when(keycloakService.resetCredentials(resetCredentialModel)).thenThrow(new Exception("Error resetting the password"));
        assertThrows(Exception.class, () -> authController.resetCredentials(resetCredentialModel));
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy not satisfied Password without number, Expect to return error")
    public void testRegisterUserModelWithoutNumber() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("AdminTest*"); // Invalid password

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy not satisfied Password without special char, Expect to return error")
    public void testRegisterUserModelWithoutSpatialchar() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("AdminTest*"); // Invalid password

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy not satisfied Password without upper case char, Expect to return error")
    public void testRegisterUserModelWithoutUppercaseChars() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("admintest01*"); // Invalid password

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy not satisfied Password less than 8 char, Expect to return error")
    public void testRegisterUserModelPassLessThanMinChar() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("Admin1*"); // Invalid password

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy satisfied, Expect to return success")
    public void testRegisterUserModelValidPassword() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("Admin01*");

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with password policy not satisfied Password max 255 char, Expect to return error")
    public void testRegisterUserModelPassMaxChar() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("test");
        registerUser.setLastName("test");
        registerUser.setPhone("9999999999");
        registerUser.setPassword("A1!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefgsa"); // Invalid password

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        System.out.println(violations);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with empty string for optional fields, Expect to pass test")
    public void testRegisterUserModelEmptyOptinalfields() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("Tdei");
        registerUser.setLastName("");
        registerUser.setPhone("");
        registerUser.setPassword("Admin01*");

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        System.out.println(violations);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with empty firstname, Expect to return error")
    public void testRegisterUserModelRequiredFirstName() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("");
        registerUser.setLastName("");
        registerUser.setPhone("");
        registerUser.setPassword("Admin01*");

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        System.out.println(violations);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("When validating the RegisterUser with firstname chars > 255, Expect to return error")
    public void testRegisterUserModelRequiredFirstNameGt255() {
        RegisterUser registerUser = new RegisterUser();
        registerUser.setEmail("test@email.com");
        registerUser.setFirstName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        registerUser.setLastName("");
        registerUser.setPhone("");
        registerUser.setPassword("Admin01*");

        Set<ConstraintViolation<RegisterUser>> violations = validator.validate(registerUser);
        System.out.println(violations);
        assertFalse(violations.isEmpty());
    }


    @Test
    @DisplayName("When regenerating API key for valid user, Expect to return new API key")
    void regenerateAPIKeyValidUser() throws Exception {
        doReturn("new_api_key").when(keycloakService).regenerateAPIKey(anyString());

        var response = authController.regenerateAPIKey("test_username");

        assertThat(response.getBody()).isEqualTo("new_api_key");
    }

    @Test
    @DisplayName("When regenerating API key for non-existing user, Expect to throw ResourceNotFoundException")
    void regenerateAPIKeyNonExistingUser() throws Exception {
        doThrow(new ResourceNotFoundException("User not found")).when(keycloakService).regenerateAPIKey(anyString());

        assertThrows(ResourceNotFoundException.class, () -> authController.regenerateAPIKey("test"));
    }

    @Test
    @DisplayName("When completing SSO login with valid code and state, Expect TokenResponse")
    void ssoLoginTest() {
        SsoLoginRequest request = new SsoLoginRequest();
        request.setCode("auth_code");
        request.setState("signed_state");
        request.setClientId("tdei-portal");
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setToken("access_token");

        when(ssoStateService.validateState("signed_state"))
                .thenReturn(new SsoStateContext("https://portal.tdei.us/login", "tdei-portal"));
        when(keycloakClientResolver.resolveClientId("tdei-portal")).thenReturn("tdei-portal");
        when(keycloakService.exchangeAuthorizationCode("auth_code", "https://portal.tdei.us/login", "tdei-portal"))
                .thenReturn(tokenResponse);

        var response = authController.ssoLogin(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(tokenResponse);
    }

    @Test
    @DisplayName("When completing SSO login with mismatched client_id, Expect InvalidCredentialsException")
    void ssoLoginMismatchedClientTest() {
        SsoLoginRequest request = new SsoLoginRequest();
        request.setCode("auth_code");
        request.setState("signed_state");
        request.setClientId("other-client");

        when(ssoStateService.validateState("signed_state"))
                .thenReturn(new SsoStateContext("https://portal.tdei.us/login", "tdei-portal"));
        when(keycloakClientResolver.resolveClientId("other-client")).thenReturn("other-client");

        assertThrows(InvalidCredentialsException.class, () -> authController.ssoLogin(request));
        verify(keycloakService, never()).exchangeAuthorizationCode(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("When initiating SSO redirect with valid redirect_uri, Expect redirect to Keycloak")
    void ssoRedirectTest() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        String redirectUri = "https://portal.tdei.us/login";
        String clientId = "tdei-portal";
        String state = "jwt-state";
        String keycloakUrl = "https://account.tdei.us/realms/tdei/protocol/openid-connect/auth?state=jwt-state";

        doNothing().when(ssoRedirectValidator).validateRedirectUri(redirectUri);
        when(keycloakClientResolver.resolveClientId(clientId)).thenReturn(clientId);
        when(ssoStateService.createState(redirectUri, clientId)).thenReturn(state);
        when(keycloakService.buildAuthorizationRedirectUrl(redirectUri, state, clientId)).thenReturn(keycloakUrl);

        authController.ssoRedirect(redirectUri, clientId, response);

        verify(ssoRedirectValidator).validateRedirectUri(redirectUri);
        verify(keycloakClientResolver).resolveClientId(clientId);
        verify(ssoStateService).createState(redirectUri, clientId);
        verify(keycloakService).buildAuthorizationRedirectUrl(redirectUri, state, clientId);
        verify(response).sendRedirect(keycloakUrl);
    }

    @Test
    @DisplayName("When initiating SSO redirect with malformed redirect_uri, Expect InvalidSsoRequestException")
    void ssoRedirectMalformedUriTest() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        String redirectUri = "http://portal.tdei.us/login";

        doThrow(new InvalidSsoRequestException("redirect_uri must use https"))
                .when(ssoRedirectValidator).validateRedirectUri(redirectUri);

        assertThrows(InvalidSsoRequestException.class, () -> authController.ssoRedirect(redirectUri, "tdei-portal", response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    @DisplayName("When completing SSO login with invalid state, Expect InvalidCredentialsException")
    void ssoLoginInvalidStateTest() {
        SsoLoginRequest request = new SsoLoginRequest();
        request.setCode("auth_code");
        request.setState("invalid_state");

        when(ssoStateService.validateState("invalid_state"))
                .thenThrow(new InvalidCredentialsException("Invalid or expired SSO state"));

        assertThrows(InvalidCredentialsException.class, () -> authController.ssoLogin(request));
        verify(keycloakService, never()).exchangeAuthorizationCode(anyString(), anyString(), anyString());
    }
}
