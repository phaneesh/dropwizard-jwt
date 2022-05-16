package io.dropwizard.auth.jwt.core;

import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import org.jose4j.jwt.JwtClaims;

import javax.security.auth.Subject;
import java.security.Principal;

@Data
@Builder
public class JwtUser implements Principal {

    private final JwtClaims claims;

    @SneakyThrows
    @Override
    public String getName() {
        return claims.getSubject();
    }

    @Override
    public boolean implies(Subject subject) {
        return Principal.super.implies(subject);
    }
}