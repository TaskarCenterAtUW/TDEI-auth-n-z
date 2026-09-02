package com.tdei.auth.core.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@ConfigurationPropertiesBinding
public class KeycloakClientsConverter implements Converter<String, Map<String, String>> {

    @Override
    public Map<String, String> convert(String source) {
        return KeycloakClientsParser.parse(source);
    }
}
