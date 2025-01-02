package com.tdei.auth.model.auth.dto;

import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Data
@Validated
public class RegisterUser {
    @Length(min = 1, max = 255)
    private String firstName;
    @Length(min = 1, max = 255)
    private String lastName;
    @NotNull
    @NotEmpty
    @Email()
    @Length(min = 1, max = 255)
    private String email;
    @Length(min = 8, max = 15)
    private String phone;
    @NotNull
    @NotEmpty
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~])(?!.*\\s).{8,255}$",
            message = "Password policy not satisfied. Min 8 & Max 255 characters length, at least 1 uppercase letter, 1 special character, and 1 numeral (0-9)."
    )
    @Length(min = 8, max = 255)
    private String password;
}
