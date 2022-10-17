package com.tdei.auth.controller.authentication;

import com.tdei.auth.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.controller.authentication.contract.IAuthentication;
import com.tdei.auth.mapper.TokenMapper;
import com.tdei.auth.mapper.UserProfileMapper;
import com.tdei.auth.model.dto.auth.TokenResponse;
import com.tdei.auth.model.dto.auth.UserProfile;
import com.tdei.auth.model.dto.common.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.service.KeycloakService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.InvalidKeyException;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Authentication", description = "Authentication operations")
public class Authentication implements IAuthentication {

    @Autowired
    KeycloakService keycloakService;

    @Override
    public ResponseEntity<UserProfile> validateApiKey(@RequestBody String apiKey) throws InvalidKeyException {
        Optional<UserRepresentation> user = keycloakService.getUserByApiKey(apiKey);
        return ResponseEntity.ok(UserProfileMapper.INSTANCE.fromUserRepresentation(user.get()));
    }

    @Override
    public ResponseEntity<UserProfile> validateAccessToken(String token) throws InvalidAccessTokenException {
        Optional<KUserInfo> user = keycloakService.getUserByAccessToken(token);
        return ResponseEntity.ok(UserProfileMapper.INSTANCE.fromKUserInfo(user.get()));
    }

    @Override
    public ResponseEntity<TokenResponse> authenticate(@RequestBody LoginModel loginModel) {
        AccessTokenResponse accessTokenResponse = keycloakService.getUserToken(loginModel);
        TokenResponse token = TokenMapper.INSTANCE.fromAccessTokenResponse(accessTokenResponse);
        return ResponseEntity.ok(token);
    }
}
