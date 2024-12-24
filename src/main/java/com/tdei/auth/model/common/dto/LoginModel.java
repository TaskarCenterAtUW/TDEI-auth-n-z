package com.tdei.auth.model.common.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Schema(description = "Describes a login information.")
@Validated
@Data
public class LoginModel {
    @Schema(required = true, description = "Username.")
    @NotNull
    @Length(min = 1, max = 255)
    private String username;
    @Schema(required = true, description = "password", example = "Password@123")
    @NotNull
//    @Pattern(
//            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~])(?!.*\\s).{8,255}$",
//            message = "Invalid credentials."
//    )
    @Length(min = 8, max = 255)
    private String password;
}
