package com.tdei.auth.repository.contract;

import com.tdei.auth.model.auth.dto.UserRoles;

import java.util.List;

public interface IUserManagementRepository {
    List<UserRoles> getUserRoles(String userId);
}
