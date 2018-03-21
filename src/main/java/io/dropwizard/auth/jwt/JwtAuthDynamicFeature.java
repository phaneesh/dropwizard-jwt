package io.dropwizard.auth.jwt;

import io.dropwizard.auth.jwt.annotation.JwtAuthRequired;
import io.dropwizard.auth.jwt.core.JwtUser;
import io.dropwizard.auth.jwt.util.TokenUtils;
import lombok.Builder;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.stream.Stream;

public class JwtAuthDynamicFeature implements DynamicFeature {

    private final JwtAuthorizer authorizer;

    @Builder
    public JwtAuthDynamicFeature(final JwtAuthorizer authorizer) {
        this.authorizer = authorizer;
    }

    public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
        final Method resourceMethod = resourceInfo.getResourceMethod();
        if (resourceMethod != null) {
            Stream.of(resourceMethod.getParameterAnnotations())
                    .flatMap(Arrays::stream)
                    .filter(annotation -> annotation.annotationType().equals(JwtAuthRequired.class))
                    .map(JwtAuthRequired.class::cast)
                    .findFirst()
                    .ifPresent(authRequired -> featureContext.register(getAuthFilter()));
        }
    }

    private ContainerRequestFilter getAuthFilter() {
        return containerRequestContext -> {
            final String authHeader = containerRequestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
            if (authHeader == null) {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }
            final String token = authHeader.startsWith("Bearer:") ? authHeader.replace("Bearer:", "").trim() : authHeader;
            JwtUser user;
            try {
               user = TokenUtils.verify(JwtAuthBundle.getKey(), token);
               if(authorizer != null) {
                   if(!authorizer.authorize(user.getClaims(), containerRequestContext)) {
                       throw new WebApplicationException(Response.Status.UNAUTHORIZED);
                   }
               }
            } catch (Exception e) {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }
            containerRequestContext.setProperty("user", user);
        };
    }
}