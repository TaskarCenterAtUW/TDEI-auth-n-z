package com.tdei.auth.model.auth.dto;

import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Data
@Validated
public class RegisterUser {
    private String firstName;
    private String lastName;
    @NotNull
    @NotEmpty
    @Email()
    private String email;
    private String phone;
    @NotNull
    @NotEmpty
    @Pattern(regexp = "^(?=(.*[a-z]){1,})(?=(.*[A-Z]){1,})(?=(.*[0-9]){1,})(?=(.*[!@#$%^&*()\\-__+.]){1,}).{8,}$", message = "Password policy not satisfied. " +
            ">8 characters length, atleast 1 letter in Upper Case, atleast 1 Special Character (!@#$&*()), atleast 1 numeral (0-9)")
    private String password;
}
