package io.dropwizard.auth.jwt.resources;

import com.codahale.metrics.annotation.Metered;
import io.dropwizard.auth.jwt.config.JwtAuthConfig;
import io.dropwizard.auth.jwt.core.TokenRequest;
import io.dropwizard.auth.jwt.core.TokenResponse;
import io.dropwizard.auth.jwt.util.TokenUtils;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;

import javax.inject.Singleton;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.security.Key;

@Path("/jwt/v1")
@Slf4j
@Singleton
public class TokenResource {

    private Key key;

    @Builder
    public TokenResource(JwtAuthConfig authConfig) {
        this.key = new AesKey(authConfig.getKey().getBytes());
    }


    @Path("/token/generate")
    @POST
    @Metered
    public Response generate(TokenRequest tokenRequest) {
        try {
            String token = TokenUtils.generate(key, tokenRequest);
            return Response.ok(TokenResponse.builder().token(token).build()).build();
        } catch(JoseException je) {
            throw new WebApplicationException(ExceptionUtils.getRootCauseMessage(je), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

}
