package com.tdei.auth.model.dto.common;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Schema(description = "Describes a login information.")
@Validated
@Data
public class LoginModel {
    @Schema(required = true, description = "Username.")
    @NotNull
    private String username;
    @Schema(required = true, description = "password")
    @NotNull
    private String password;
}
