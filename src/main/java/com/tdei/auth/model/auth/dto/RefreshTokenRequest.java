package com.tdei.auth.model.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@Schema(description = "Refresh token request.")
public class RefreshTokenRequest {

    @NotBlank
    @Schema(description = "Refresh token issued by Keycloak")
    private String refreshToken;

    @Schema(description = "Keycloak client id that issued the tokens. Defaults to default-client-id when omitted.")
    private String clientId;
}
