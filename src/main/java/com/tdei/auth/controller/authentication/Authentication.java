package com.tdei.auth.controller.authentication;

import com.tdei.auth.controller.authentication.contract.IAuthentication;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.mapper.TokenMapper;
import com.tdei.auth.mapper.UserProfileMapper;
import com.tdei.auth.model.auth.dto.RegisterUser;
import com.tdei.auth.model.auth.dto.TokenResponse;
import com.tdei.auth.model.auth.dto.UserProfile;
import com.tdei.auth.model.common.dto.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.service.KeycloakService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.security.InvalidKeyException;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
@Tag(name = "Authentication", description = "Authentication operations")
public class Authentication implements IAuthentication {

    private final KeycloakService keycloakService;

    @Override
    public ResponseEntity<UserProfile> validateApiKey(@RequestBody String apiKey) throws InvalidKeyException {
        Optional<UserRepresentation> user = keycloakService.getUserByApiKey(apiKey.replaceAll("^\"|\"$", ""));
        return ResponseEntity.ok(UserProfileMapper.INSTANCE.fromUserRepresentation(user.get()));
    }

    @Override
    public ResponseEntity<UserProfile> validateAccessToken(String token) throws InvalidAccessTokenException {
        Optional<KUserInfo> user = keycloakService.getUserByAccessToken(token.replaceAll("^\"|\"$", ""));
        return ResponseEntity.ok(UserProfileMapper.INSTANCE.fromKUserInfo(user.get()));
    }

    @Override
    public ResponseEntity<TokenResponse> authenticate(@RequestBody LoginModel loginModel) {
        AccessTokenResponse accessTokenResponse = keycloakService.getUserToken(loginModel);
        TokenResponse token = TokenMapper.INSTANCE.fromAccessTokenResponse(accessTokenResponse);
        return ResponseEntity.ok(token);
    }

    @Override
    public ResponseEntity<Boolean> hasPermission(String userId, Optional<String> agencyId, String[] roles, Optional<Boolean> affirmative) {
        return ResponseEntity.ok(keycloakService.hasPermission(userId, agencyId, roles, affirmative));
    }

    @Override
    public ResponseEntity<UserProfile> registerUser(@Valid @RequestBody RegisterUser user) throws Exception {
        return ResponseEntity.ok(keycloakService.registerUser(user));
    }

    @Override
    public ResponseEntity<UserProfile> getUserByUserName(String userName) throws Exception {
        var profile = keycloakService.getUserByUserName(userName);
        if (profile == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(profile);
    }

    @Override
    public ResponseEntity<TokenResponse> reIssueToken(@RequestBody String refreshToken) {
        TokenResponse accessTokenResponse = keycloakService.reIssueToken(refreshToken.replaceAll("^\"|\"$", ""));
        return ResponseEntity.ok(accessTokenResponse);
    }

    @Override
    public ResponseEntity<String> generateSecret() {
        String secret = keycloakService.generateSecret();
        return ResponseEntity.ok(secret);
    }

    @Override
    public ResponseEntity<String> validateSecret(@RequestBody String secret) {
        Boolean result = keycloakService.validateSecret(secret.replaceAll("^\"|\"$", ""));
        return ResponseEntity.ok(result.toString());
    }
}
