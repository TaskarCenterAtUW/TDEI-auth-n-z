package com.tdei.auth.model.common.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Schema(description = "Describes a reset credential model.")
@Validated
@Data
public class ResetCredentialModel {
    @Schema(required = true, description = "user name.")
    @NotNull
    @Length(min = 1, max = 255)
    private String username;
    @Schema(required = true, description = "password", example = "Password@123")
    @NotNull
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~])(?!.*\\s).{8,255}$",
            message = "Password policy not satisfied. Min 8 & Max 255 characters length, at least 1 uppercase letter, 1 special character, and 1 numeral (0-9)."
    )
    @Length(min = 8, max = 255)
    private String password;
}


