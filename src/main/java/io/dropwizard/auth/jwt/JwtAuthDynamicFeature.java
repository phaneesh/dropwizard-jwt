package io.dropwizard.auth.jwt;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.dropwizard.auth.jwt.annotation.JwtAuthParam;
import io.dropwizard.auth.jwt.annotation.JwtAuthRequired;
import io.dropwizard.auth.jwt.config.JwtAuthBundleConfiguration;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

public class JwtAuthDynamicFeature implements DynamicFeature {

    private final JwtAuthorizer authorizer;

    private static JwtAuthBundleConfiguration configuration;

    private static LoadingCache<String, JwtUser> tokenCache;

    @Builder
    public JwtAuthDynamicFeature(final JwtAuthBundleConfiguration configuration, final JwtAuthorizer authorizer) {
        this.configuration = configuration;
        this.authorizer = authorizer;
        tokenCache = Caffeine.newBuilder()
                .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                .maximumSize(configuration.getCacheMaxSize())
                .build(JwtAuthDynamicFeature::getUser);
    }

    public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
        final Method resourceMethod = resourceInfo.getResourceMethod();
        if (resourceMethod != null) {
            Stream.of(resourceMethod.getParameterAnnotations())
                    .flatMap(Arrays::stream)
                    .filter(annotation -> annotation.annotationType().equals(JwtAuthRequired.class))
                    .map(JwtAuthRequired.class::cast)
                    .findFirst()
                    .ifPresent(authRequired -> featureContext.register(getAuthFilter(authRequired)));
        }
    }

    private static JwtUser getUser(String token) {
        try {
            return TokenUtils.verify(JwtAuthBundle.getKey(), token, configuration);
        } catch (Exception e) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }
    }

    private ContainerRequestFilter getAuthFilter(JwtAuthRequired authRequired) {
        return containerRequestContext -> {
            final String authHeader = containerRequestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
            if (authHeader == null) {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }
            final String token = authHeader.startsWith("Bearer:") ? authHeader.replace("Bearer:", "").trim() : authHeader;
            JwtUser user;
            try {
                user = tokenCache.get(token);
                boolean authorize = false;
                for (String audience : authRequired.value()) {
                    if (user.getClaims().getAudience().contains(audience)) {
                        authorize = true;
                        break;
                    }
                }

                if (authRequired.authParams() != null && authRequired.authParams().length > 0) {
                    for(JwtAuthParam param : authRequired.authParams()) {
                        if (user.getClaims().hasClaim(param.name()) &&
                                user.getClaims().isClaimValueOfType(param.name(), ArrayList.class)) {
                            if (Collections.disjoint(Arrays.asList(param.value()),
                                    user.getClaims().getClaimValue(param.name(), ArrayList.class))) {
                                authorize = false;
                                break;
                            }
                        }
                    }
                }

                if (authorize) {
                    if (authorizer != null) {
                        if (!authorizer.authorize(user.getClaims(), containerRequestContext)) {
                            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
                        }
                    }
                } else {
                    throw new WebApplicationException(Response.Status.UNAUTHORIZED);
                }
            } catch (Exception e) {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }
            containerRequestContext.setProperty("user", user);
        };
    }
}