package com.tdei.auth.model.auth.dto;

import lombok.Data;

@Data
public class UserProfile {
    private String id;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String apiKey;
    private boolean emailVerified;
    private String username;
}
