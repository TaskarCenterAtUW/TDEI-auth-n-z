package com.tdei.auth.model.auth.dto;

import lombok.Data;

@Data
public class UserRoles {
    private String userId;
    private String projectGroupId;
    private String roleId;
    private String roleName;
}
