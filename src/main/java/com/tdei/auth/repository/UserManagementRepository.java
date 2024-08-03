package com.tdei.auth.repository;

import com.tdei.auth.model.auth.dto.UserRoles;
import com.tdei.auth.repository.contract.IUserManagementRepository;
import com.tdei.auth.repository.mappers.RolesRowMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserManagementRepository implements IUserManagementRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public List<UserRoles> getUserRoles(String userId) {
        try {
            String sql = "SELECT ur.*, r.name FROM user_roles ur\n" +
                    " INNER JOIN roles r on r.role_id = ur.role_id\n" +
                    " WHERE ur.user_id = '" + userId + "'";
            return jdbcTemplate.query(sql, new RolesRowMapper());
        } catch (DataAccessException e) {
            System.out.println(e);
            throw new RuntimeException("Error fetching the roles.");
        } catch (Exception e) {
            System.out.println(e);
            throw new RuntimeException("Error fetching the roles.");
        }
    }
}
