package com.tdei.auth.model.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SsoStateContext {
    private String redirectUri;
    private String clientId;
}
