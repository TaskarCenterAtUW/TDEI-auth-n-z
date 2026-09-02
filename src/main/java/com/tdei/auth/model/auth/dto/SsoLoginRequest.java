package com.tdei.auth.model.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@Schema(description = "SSO login request with authorization code and state from Keycloak callback.")
public class SsoLoginRequest {

    @NotBlank
    @Schema(description = "Authorization code returned by Keycloak")
    private String code;

    @NotBlank
    @Schema(description = "State parameter returned by Keycloak")
    private String state;

    @Schema(description = "Keycloak client id used to initiate SSO. Defaults to default-client-id when omitted.")
    private String clientId;
}
