package com.tdei.auth.model.dto.auth;

import lombok.Data;

@Data
public class ClientCreds {
    private String client_id;
    private String client_secret;
}
