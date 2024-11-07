package com.tdei.auth.model.common.dto;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.util.List;

@Schema(description = "Describes a trigger email information.")
@Validated
@Data
public class TriggerEmailModel {
    @Schema(required = true, description = "Username.")
    @NotNull
    String username;
    @Schema(required = true, description = "Email actions.")
    @NotNull
    @ArraySchema(minItems = 1, schema = @Schema(implementation = EmailActions.class))
    List<EmailActions> email_actions;
}
