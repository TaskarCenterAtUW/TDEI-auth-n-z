package com.tdei.auth.core.config;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

@Component
public class JwtSigningKeyProvider {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;

    private final ApplicationProperties applicationProperties;

    public JwtSigningKeyProvider(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public Key getSigningKey() {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(
                applicationProperties.getSpring().getApplication().getSecret());
        return new SecretKeySpec(apiKeySecretBytes, SIGNATURE_ALGORITHM.getJcaName());
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return SIGNATURE_ALGORITHM;
    }
}
