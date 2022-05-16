package io.dropwizard.auth.jwt.util;

import io.dropwizard.auth.jwt.core.JwtUser;
import io.dropwizard.auth.jwt.core.TokenRequest;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.lang.JoseException;

import java.util.Map;

public interface TokenUtils {

    static String generate(JsonWebEncryption jwe, TokenRequest tokenRequest) throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(tokenRequest.getSubject());
        claims.setIssuedAtToNow();
        claims.setAudience(tokenRequest.getAudience());
        claims.setGeneratedJwtId();
        for (Map.Entry<String, Object> entry : tokenRequest.getClaims().entrySet()) {
            claims.setClaim(entry.getKey(), entry.getValue());
        }
        if (tokenRequest.getExpiresOn() != null) {
            claims.setExpirationTime(NumericDate.fromMilliseconds(tokenRequest.getExpiresOn().getTime()));
        }
        jwe.setPayload(claims.toJson());
        return jwe.getCompactSerialization();
    }

    static JwtUser verify(JwtConsumer jwtConsumer, String token) throws InvalidJwtException {
        JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        return JwtUser.builder()
                .claims(jwtClaims)
                .build();
    }
}
