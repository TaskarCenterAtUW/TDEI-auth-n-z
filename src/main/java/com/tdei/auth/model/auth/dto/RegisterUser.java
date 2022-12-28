package com.tdei.auth.model.auth.dto;

import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Data
@Validated
public class RegisterUser {
    private String firstName;
    private String lastName;
    @NotNull
    @NotEmpty
    private String email;
    private String phone;
    @NotNull
    @NotEmpty
    private String password;
}
