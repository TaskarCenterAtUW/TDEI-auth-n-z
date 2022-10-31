package com.tdei.auth.model.auth.dto;

import lombok.Data;

@Data
public class UserProfile {
    private String id;
    private String firstName;
    private String lastName;
    private String email;
    private boolean email_verified;
    private String username;
}
