package io.dropwizard.auth.jwt;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.dropwizard.auth.jwt.annotation.JwtAuthParam;
import io.dropwizard.auth.jwt.annotation.JwtAuthRequired;
import io.dropwizard.auth.jwt.core.JwtUser;
import io.dropwizard.auth.jwt.util.TokenUtils;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtConsumer;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Slf4j
public class JwtAuthDynamicFeature implements DynamicFeature {

    public static final String AUTHORIZED_FOR_SUBJECT = "X-AUTHORIZED-FOR-SUBJECT";
    public static final String AUTHORIZED_FOR_MASK = "X-AUTHORIZED-FOR-%s";

    private final JwtAuthorizer authorizer;
    private final JwtConsumer jwtConsumer;

    private final LoadingCache<String, JwtUser> tokenCache;

    @Builder
    public JwtAuthDynamicFeature(final JwtConsumer jwtConsumer, final int cacheExpiry, final int cacheSize, final JwtAuthorizer authorizer) {
        this.jwtConsumer = jwtConsumer;
        this.authorizer = authorizer;
        tokenCache = Caffeine.newBuilder()
                .expireAfterWrite(cacheExpiry, TimeUnit.SECONDS)
                .maximumSize(cacheSize)
                .build(this::getUser);
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        var authRequired = resourceInfo.getResourceMethod().getAnnotation(JwtAuthRequired.class);
        if (Objects.nonNull(authRequired)) {
            context.register(getAuthFilter(authRequired));
        }
    }

    private JwtUser getUser(String token) {
        try {
            return TokenUtils.verify(jwtConsumer, token);
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
                    if(audience.equals("*")) {
                        authorize = true;
                        break;
                    }
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
            try {
                stampHeaders(containerRequestContext, user.getClaims());
            } catch (MalformedClaimException e) {
                log.error("Cannot stamp headers for user: {} | Error: {}", user.getName(), e);
            }
        };
    }

    public void stampHeaders(ContainerRequestContext requestContext, JwtClaims jwtClaims) throws MalformedClaimException {
        requestContext.getHeaders().putSingle(AUTHORIZED_FOR_SUBJECT, jwtClaims.getSubject());
        jwtClaims.flattenClaims().forEach( (s, objects) -> {
            requestContext.getHeaders().putSingle(String.format(AUTHORIZED_FOR_MASK, s), String.valueOf(objects));
        });
    }
}