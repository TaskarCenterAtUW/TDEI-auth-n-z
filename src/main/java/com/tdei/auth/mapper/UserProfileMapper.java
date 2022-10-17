package com.tdei.auth.mapper;

import com.tdei.auth.model.dto.auth.UserProfile;
import com.tdei.auth.model.keycloak.KUserInfo;
import org.keycloak.representations.idm.UserRepresentation;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserProfileMapper {
    UserProfileMapper INSTANCE = Mappers.getMapper(UserProfileMapper.class);

    UserProfile fromUserRepresentation(UserRepresentation user);

    @Mapping(source = "family_name", target = "lastName")
    @Mapping(source = "sub", target = "id")
    @Mapping(source = "preferred_username", target = "username")
    @Mapping(source = "given_name", target = "firstName")
    UserProfile fromKUserInfo(KUserInfo user);
}
