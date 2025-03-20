package io.dropwizard.auth.jwt;

import jakarta.ws.rs.container.ContainerRequestContext;
import org.jose4j.jwt.JwtClaims;



public interface JwtAuthorizer {

    boolean authorize(JwtClaims claims, ContainerRequestContext containerRequestContext);
}
