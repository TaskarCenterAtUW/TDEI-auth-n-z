package com.tdei.auth.model.auth.dto;

import lombok.Data;

@Data
public class ClientCreds {
    private String client_id;
    private String client_secret;
}
