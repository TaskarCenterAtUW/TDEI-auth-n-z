package com.tdei.auth.service;

import com.tdei.auth.constants.RoleConstants;
import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.mapper.UserProfileMapper;
import com.tdei.auth.model.auth.dto.ClientCreds;
import com.tdei.auth.model.auth.dto.RegisterUser;
import com.tdei.auth.model.auth.dto.UserProfile;
import com.tdei.auth.model.common.dto.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.repository.UserManagementRepository;
import com.tdei.auth.service.contract.IKeycloakService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.*;

@RequiredArgsConstructor
@Service
@Slf4j
public class KeycloakService implements IKeycloakService {
    private final Keycloak keycloakInstance;
    private final ApplicationProperties applicationProperties;

    @Autowired
    UserManagementRepository userManagementRepository;

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
    public Boolean hasPermission(String userId, Optional<String> orgId, String[] roles, Optional<Boolean> affirmative) {
        Boolean satisfied = false;

        var userRoles = userManagementRepository.getUserRoles(userId);

        //Sytem admin check, person is allowed to do all action
        if (userRoles.stream().anyMatch(x -> x.getRoleName().equalsIgnoreCase(RoleConstants.TDEI_ADMIN)))
            return true;

        //Check if role exists
        if (orgId.isPresent() && !orgId.get().isEmpty()) {
            if (userRoles.stream().anyMatch(x -> (x.getOrgId().equals(orgId.get())) &&
                    (affirmative.isPresent() && affirmative.get() ?
                            Arrays.stream(roles).allMatch(y -> y.equalsIgnoreCase(x.getRoleName()))
                            : Arrays.stream(roles).anyMatch(y -> y.equalsIgnoreCase(x.getRoleName())))
            ))
                satisfied = true;
            else
                satisfied = false;
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

    public UserProfile registerUser(RegisterUser userDto) throws Exception {
        try {
            UsersResource usersResource = getUserInstance();

            UserRepresentation user = new UserRepresentation();
            if (!userDto.getFirstName().isEmpty())
                user.setFirstName(userDto.getFirstName());
            if (!userDto.getLastName().isEmpty())
                user.setLastName(userDto.getLastName());
            user.setUsername(userDto.getEmail());
            user.setEmailVerified(true);
            user.setEnabled(true);

            //Set user attributes
            if (userDto.getPhone() != null && !userDto.getPhone().isEmpty()) {
                Map<String, List<String>> attributes = new HashMap<>();
                attributes.put("phone", List.of(userDto.getPhone()));
                user.setAttributes(attributes);
            }

            //Set the credentials
            CredentialRepresentation cred = new CredentialRepresentation();
            cred.setType(CredentialRepresentation.PASSWORD);
            cred.setValue(userDto.getPassword());
            cred.setTemporary(false);
            user.setCredentials(List.of(cred));

            var createdUserRes = usersResource.create(user);
            if (createdUserRes.getStatus() == 201) {
                String userId = createdUserRes.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                var createdUser = usersResource.get(userId).toRepresentation();

                var userProfile = UserProfileMapper.INSTANCE.fromUserRepresentation(createdUser);
                if (createdUser.getAttributes().get("phone") != null)
                    userProfile.setPhone(createdUser.getAttributes().get("phone").get(0).toString());
                return userProfile;
            }
        } catch (Exception e) {
            log.error("Failed registering the user", e);
            throw new Exception("Failed registering the user");
        }
        return null;
    }

    public UserProfile getUserByUserName(String userName) throws Exception {
        try {
            UsersResource usersResource = getUserInstance();
            List<UserRepresentation> user = usersResource.search(userName, true);

            if (user == null || user.isEmpty())
                return null;

            var userInfo = user.stream().findFirst().get();

            var userProfile = UserProfileMapper.INSTANCE.fromUserRepresentation(userInfo);
            if (userInfo.getAttributes().get("phone") != null)
                userProfile.setPhone(userInfo.getAttributes().get("phone").toString());
            return userProfile;
        } catch (Exception e) {
            log.error("Error fetching the user information", e);
            throw new Exception("Error fetching the user information");
        }
    }

    private UserResource getUserByUserId(String userId) {
        UsersResource usersResource = getUserInstance();
        UserResource user = usersResource.get(userId);

        if (user == null)
            return null;

        return user;
    }
}