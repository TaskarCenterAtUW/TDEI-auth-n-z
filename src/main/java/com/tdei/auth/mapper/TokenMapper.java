package com.tdei.auth.mapper;

import com.tdei.auth.model.dto.auth.TokenResponse;
import org.keycloak.representations.AccessTokenResponse;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface TokenMapper {

    TokenMapper INSTANCE = Mappers.getMapper(TokenMapper.class);

    TokenResponse fromAccessTokenResponse(AccessTokenResponse tokenResponse);
}
