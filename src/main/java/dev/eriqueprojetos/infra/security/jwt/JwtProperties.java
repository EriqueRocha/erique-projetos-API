package dev.eriqueprojetos.infra.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;


@Configuration
@ConfigurationProperties(prefix = "jwt.properties")
public class JwtProperties {

    public static String PREFIX;
    public static String KEY;

    public void setPrefix(String prefix){
        PREFIX = prefix;
    }

    public String getPrefix() {
        return PREFIX;
    }

    public void setKey(String key){
        KEY = key;
    }

    public String getKey() {
        return KEY;
    }

}
