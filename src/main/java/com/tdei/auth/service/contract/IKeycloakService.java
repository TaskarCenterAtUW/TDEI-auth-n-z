package com.tdei.auth.service.contract;

import com.tdei.auth.model.keycloak.KUserInfo;
import org.keycloak.representations.idm.UserRepresentation;

import java.security.InvalidKeyException;
import java.util.Optional;

public interface IKeycloakService {

    Optional<UserRepresentation> getUserByApiKey(String apiKey) throws InvalidKeyException;

    Optional<KUserInfo> getUserByAccessToken(String accessToken);
}
