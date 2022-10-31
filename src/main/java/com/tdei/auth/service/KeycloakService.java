package com.tdei.auth.service;

import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.model.auth.dto.ClientCreds;
import com.tdei.auth.model.common.dto.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.service.contract.IKeycloakService;
import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class KeycloakService implements IKeycloakService {
    private final Keycloak keycloakInstance;
    private final ApplicationProperties applicationProperties;

    private boolean checkUserExists(String userName) {
        return getUserByUserName(userName) != null;
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

    @Override
    public Boolean hasPermission(String userId, Optional<String> agencyId, String[] roles, Optional<Boolean> affirmative) {
        UserResource user = getUserByUserId(userId);

        //TODO: Need to move logic to pull information from DB
        if (agencyId.isPresent()) {
            String agencies = user.toRepresentation().getAttributes().get("agencies").toString();
            if (!agencies.contains(agencyId.get())) return false;
        }

        var roleList = user.roles().getAll().getRealmMappings();
        if (roleList == null || roleList.isEmpty()) return false;
        Boolean satisfied = false;
        if (affirmative.isPresent() && affirmative.get()) {
            //User should match at least one role
            satisfied = Arrays.stream(roles).anyMatch(x -> roleList.stream().anyMatch(s -> s.getName().equals(x)));
        } else {
            //User should have all roles defined
            satisfied = Arrays.stream(roles).allMatch(x -> roleList.stream().anyMatch(s -> s.getName().equals(x)));
        }
        return satisfied;
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

    private UserRepresentation getUserByUserName(String userName) {
        UsersResource usersResource = getUserInstance();
        List<UserRepresentation> user = usersResource.search(userName, true);

        if (user == null || user.isEmpty())
            return null;

        return user.stream().findFirst().get();
    }

    private UserResource getUserByUserId(String userId) {
        UsersResource usersResource = getUserInstance();
        UserResource user = usersResource.get(userId);

        if (user == null)
            return null;

        return user;
    }
}