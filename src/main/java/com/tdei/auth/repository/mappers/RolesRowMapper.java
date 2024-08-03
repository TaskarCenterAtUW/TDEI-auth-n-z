package com.tdei.auth.repository.mappers;

import com.tdei.auth.model.auth.dto.UserRoles;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RolesRowMapper implements RowMapper<UserRoles> {
    @Override
    public UserRoles mapRow(ResultSet rs, int arg1) throws SQLException {
        UserRoles emp = new UserRoles();
        emp.setRoleId(rs.getString("role_id"));
        emp.setProjectGroupId(rs.getString("project_group_id"));
        emp.setUserId(rs.getString("user_id"));
        emp.setRoleName(rs.getString("name"));
        return emp;
    }
}
