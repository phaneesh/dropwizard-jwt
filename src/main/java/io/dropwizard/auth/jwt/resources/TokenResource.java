package io.dropwizard.auth.jwt.resources;

import com.codahale.metrics.annotation.Metered;
import io.dropwizard.auth.jwt.core.TokenRequest;
import io.dropwizard.auth.jwt.core.TokenResponse;
import io.dropwizard.auth.jwt.util.TokenUtils;
import jakarta.inject.Singleton;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;


@Path("/jwt/v1")
@Slf4j
@Singleton
public class TokenResource {

    private final JsonWebEncryption jwe;
    @Builder
    public TokenResource(final JsonWebEncryption jwe) {
        this.jwe = jwe;
    }

    @Path("/token/generate")
    @POST
    @Metered
    public Response generate(TokenRequest tokenRequest) {
        try {
            String token = TokenUtils.generate(jwe, tokenRequest);
            return Response.ok(TokenResponse.builder().token(token).build()).build();
        } catch(JoseException je) {
            throw new WebApplicationException(ExceptionUtils.getRootCauseMessage(je), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}
