package com.tdei.auth.model.common.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Schema(description = "Describes a reset credential model.")
@Validated
@Data
public class ResetCredentialModel {
    @Schema(required = true, description = "user name.")
    @NotNull
    private String username;
    @Schema(required = true, description = "password", example = "Password@123")
    @NotNull
    @Pattern(regexp = "^(?=(.*[a-z]){1,})(?=(.*[A-Z]){1,})(?=(.*[0-9]){1,})(?=(.*[!@#$%^&*()\\-__+.]){1,}).{8,}$", message = "Password policy not satisfied. >8 characters length, atleast 1 letter in Upper Case, atleast 1 Special Character (!@#$&*()), atleast 1 numeral (0-9)")
    private String password;
}
