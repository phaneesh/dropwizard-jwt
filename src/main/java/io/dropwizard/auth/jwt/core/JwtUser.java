package io.dropwizard.auth.jwt.core;

import lombok.Builder;
import lombok.Data;
import org.jose4j.jwt.JwtClaims;

@Data
@Builder
public class JwtUser {

    private final JwtClaims claims;

}