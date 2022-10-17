package com.tdei.auth.service;

import com.tdei.auth.config.ApplicationProperties;
import com.tdei.auth.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.model.dto.auth.ClientCreds;
import com.tdei.auth.model.dto.common.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.service.contract.IKeycloakService;
import lombok.AllArgsConstructor;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@Service
public class KeycloakService implements IKeycloakService {
    @Autowired
    Keycloak keycloakInstance;
    @Autowired
    private ApplicationProperties applicationProperties;

    private boolean checkUserExists(String userName) {
        return getUser(userName) != null;
    }

    public Optional<UserRepresentation> getUserByApiKey(String apiKey) throws InvalidKeyException {
        UsersResource instance = getUserInstance();
        List<UserRepresentation> user = instance.searchByAttributes(String.format("x-api-key:%s", apiKey));
        if (user.isEmpty()) throw new InvalidKeyException("Invalid API Key exception");
        return user.stream().findFirst();
    }

    public Optional<KUserInfo> getUserByAccessToken(String accessToken) {
        try {
            KeyclockUserClient keyclockUserClient = KeyclockUserClient.connect(applicationProperties.getKeycloakClientEndpoints().getUserUrl());
            ClientCreds creds = new ClientCreds();
            creds.setClient_id(applicationProperties.getKeycloak().getResource());
            creds.setClient_secret(applicationProperties.getKeycloak().getCredentials().getSecret());
            KUserInfo user = keyclockUserClient.userInfo(applicationProperties.getKeycloak().getResource(),
                    applicationProperties.getKeycloak().getCredentials().getSecret(),
                    accessToken);
            return Optional.of(user);
        } catch (Exception e) {
            throw new InvalidAccessTokenException("Invalid/Expired Access Token");
        }
    }

    public AccessTokenResponse getUserToken(LoginModel person) {
        AccessTokenResponse token = null;
        try {
            Keycloak keycloak = KeycloakBuilder.builder()
                    .serverUrl(applicationProperties.getKeycloak().getAuthServerUrl())
                    .realm(applicationProperties.getKeycloak().getRealm())
                    .clientId(applicationProperties.getKeycloak().getResource())
                    .clientSecret(applicationProperties.getKeycloak().getCredentials().getSecret())
                    .grantType(OAuth2Constants.PASSWORD)
                    .username(person.getUsername())
                    .password(person.getPassword())
                    .resteasyClient(new ResteasyClientBuilder()
                            .connectionPoolSize(1)
                            .build()
                    )
                    .build();

            token = keycloak.tokenManager().getAccessToken();
        } catch (Exception ex) {
            throw new InvalidCredentialsException("Invalid Credentials");
        }
        return token;
    }

    private UsersResource getUserInstance() {
        return keycloakInstance.realm(applicationProperties.getKeycloak().getRealm()).users();
    }

    private UserRepresentation getUser(String userName) {
        UsersResource usersResource = getUserInstance();
        List<UserRepresentation> user = usersResource.search(userName, true);

        if (user == null || user.isEmpty())
            return null;

        return user.stream().findFirst().get();
    }
}