package io.dropwizard.auth.jwt;

import org.jose4j.jwt.JwtClaims;

import javax.ws.rs.container.ContainerRequestContext;

public interface JwtAuthorizer {

    boolean authorize(JwtClaims claims, ContainerRequestContext containerRequestContext);
}
