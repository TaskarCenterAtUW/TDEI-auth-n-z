package com.tdei.auth.service;

import com.google.gson.internal.LinkedTreeMap;
import com.tdei.auth.constants.RoleConstants;
import com.tdei.auth.core.config.ApplicationProperties;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.core.config.exception.handler.exceptions.InvalidCredentialsException;
import com.tdei.auth.core.config.exception.handler.exceptions.UserExistsException;
import com.tdei.auth.mapper.UserProfileMapper;
import com.tdei.auth.model.auth.dto.ClientCreds;
import com.tdei.auth.model.auth.dto.RegisterUser;
import com.tdei.auth.model.auth.dto.TokenResponse;
import com.tdei.auth.model.auth.dto.UserProfile;
import com.tdei.auth.model.common.dto.LoginModel;
import com.tdei.auth.model.keycloak.KUserInfo;
import com.tdei.auth.repository.UserManagementRepository;
import com.tdei.auth.service.contract.IKeycloakService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
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

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.time.temporal.ChronoUnit;
import java.util.*;

@RequiredArgsConstructor
@Service
@Slf4j
public class KeycloakService implements IKeycloakService {
    private static SignatureAlgorithm signatureAlgorithm;
    private final Keycloak keycloakInstance;
    private final ApplicationProperties applicationProperties;

    @Autowired
    UserManagementRepository userManagementRepository;

    private Key getSigningKey() {
        //The JWT signature algorithm we will be using to sign the token
        signatureAlgorithm = SignatureAlgorithm.HS256;
        //We will sign our JWT with our ApiKey secret, which will come from env configuration
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(applicationProperties.getSpring().getApplication().getSecret());
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        return signingKey;
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
        } else {
            if (userRoles.stream().anyMatch(x ->
                    (affirmative.isPresent() && affirmative.get() ?
                            Arrays.stream(roles).allMatch(y -> y.equalsIgnoreCase(x.getRoleName()))
                            : Arrays.stream(roles).anyMatch(y -> y.equalsIgnoreCase(x.getRoleName())))
            ))
                satisfied = true;
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

    public TokenResponse reIssueToken(String refreshToken) {
        try {
            KeyclockTokenClient keyclockTokenClient = KeyclockTokenClient.connect(applicationProperties.getKeycloakClientEndpoints().getTokenUrl());
            LinkedTreeMap user = keyclockTokenClient.refreshToken(
                    applicationProperties.getKeycloak().getResource(),
                    applicationProperties.getKeycloak().getCredentials().getSecret(),
                    refreshToken,
                    "refresh_token");
            TokenResponse res = new TokenResponse();
            res.setToken(user.get("access_token").toString());
            res.setRefreshToken(user.get("refresh_token").toString());
            res.setExpiresIn(Math.round((Double) user.get("expires_in")));
            res.setRefreshExpiresIn(Math.round((Double) user.get("refresh_expires_in")));
            return res;
        } catch (Exception e) {
            throw new InvalidAccessTokenException("Invalid/Expired Access Token");
        }
    }

    @Override
    public String generateSecret() {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        //Let's set the JWT Claims
        //Builds the JWT and serializes it to a compact, URL-safe string
        String secretToken = Jwts.builder().setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setSubject("intranet communication")
                .setIssuer("tdei")
                .setExpiration(Date.from(now.toInstant().plus(applicationProperties.getSpring().getApplication().getSecretTtl(), ChronoUnit.SECONDS)))
                .signWith(getSigningKey(), signatureAlgorithm)
                .compact();
        return secretToken;
    }

    @Override
    public Boolean validateSecret(String secret) {
        try {
            //This line will throw an exception if it is not a signed JWS (as expected)
            Jws<Claims> jwt = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(secret);
        } catch (ExpiredJwtException e) {
            return false;
        } catch (UnsupportedJwtException e) {
            return false;
        } catch (MalformedJwtException e) {
            return false;
        } catch (SignatureException e) {
            return false;
        } catch (IllegalArgumentException e) {
            return false;
        }
        return true;
    }

    private UsersResource getUserInstance() {
        return keycloakInstance.realm(applicationProperties.getKeycloak().getRealm()).users();
    }

    public UserProfile registerUser(RegisterUser userDto) throws Exception {
        try {
            UsersResource usersResource = getUserInstance();

            UserRepresentation user = new UserRepresentation();
            if (!userDto.getFirstName().isEmpty())
                user.setFirstName(userDto.getFirstName().trim());
            if (!userDto.getLastName().isEmpty())
                user.setLastName(userDto.getLastName().trim());
            user.setUsername(userDto.getEmail().trim());
            user.setEmail(userDto.getEmail().trim());
            user.setEmailVerified(true);
            user.setEnabled(true);

            //Set user attributes
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("x-api-key", List.of(UUID.randomUUID().toString()));
            if (userDto.getPhone() != null && !userDto.getPhone().isEmpty()) {
                attributes.put("phone", List.of(userDto.getPhone()));
            }
            user.setAttributes(attributes);

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
            } else if (createdUserRes.getStatus() == 409) {
                throw new UserExistsException(userDto.getEmail().trim());
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
                userProfile.setPhone(userInfo.getAttributes().get("phone").stream().findFirst().get());
            if (userInfo.getAttributes().get("x-api-key") != null)
                userProfile.setApiKey(userInfo.getAttributes().get("x-api-key").stream().findFirst().get());
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