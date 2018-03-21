package io.dropwizard.auth.jwt.util;

import io.dropwizard.auth.jwt.core.JwtUser;
import io.dropwizard.auth.jwt.core.TokenRequest;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.util.Map;

public interface TokenUtils {

    static String generate(Key key, TokenRequest tokenRequest) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                KeyManagementAlgorithmIdentifiers.A256KW));
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));
        jwe.setKey(key);
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

    static JwtUser verify(Key key, String token) throws InvalidJwtException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireJwtId()
                .setAllowedClockSkewInSeconds(30)
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .setRequireSubject()
                .setDecryptionKey(key)
                .build();
        JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        return JwtUser.builder()
                .claims(jwtClaims)
                .build();
    }
}
