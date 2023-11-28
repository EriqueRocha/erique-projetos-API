package dev.eriqueprojetos.infra.security.jwt;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

public class JwtObject {

    private String subject;
    private LocalDateTime issuedAt;
    private LocalDateTime expiration;
    private List<String> roles;

    private Integer id;

    private String name;

    private static JwtObject build = null;

    public static JwtObject builder() {
        build = new JwtObject();
        return build;
    }

    public Integer getId() {
        return id;
    }

    public JwtObject setId(Integer id) {
        this.id = id;
        return this;
    }

    public String getName() {
        return name;
    }

    public JwtObject setName(String name) {
        this.name = name;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public JwtObject subject(String subject) {
        this.subject = subject;
        return this;
    }

    public LocalDateTime getIssuedAt() {
        return issuedAt;
    }

    public JwtObject issuedAt(LocalDateTime issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public JwtObject issuedAt() {
        this.issuedAt = LocalDateTime.now();
        return this;
    }

    public LocalDateTime getExpiration() {
        return expiration;
    }

    public JwtObject expirationHours(long hours) {
        this.expiration = this.issuedAt.plusHours(hours);
        return this;
    }

    public JwtObject expiration(LocalDateTime expiration) {
        this.expiration = expiration;
        return this;
    }

    public List<String> getRoles() {
        return roles;
    }

    public JwtObject roles(List<String> roles) {
        this.roles = roles;
        return this;
    }

    public JwtObject roles(String... roles) {
        this.roles = Arrays.asList(roles);
        return this;
    }

}
