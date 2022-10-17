package com.tdei.auth.model.keycloak;

import lombok.Data;

@Data
public class KUserInfo {
    
    private String sub;
    private boolean email_verified;
    private String name;
    private String preferred_username;
    private String given_name;
    private String family_name;
    private String email;
}
