package io.dropwizard.auth.jwt;

import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.jwt.config.JwtAuthBundleConfiguration;
import io.dropwizard.auth.jwt.core.JwtUser;
import io.dropwizard.auth.jwt.resources.TokenResource;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import lombok.Getter;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.AesKey;

import java.nio.charset.StandardCharsets;
import java.security.Key;

public abstract class JwtAuthBundle<T extends Configuration> implements ConfiguredBundle<T> {

  private Key key;

  @Getter
  private JwtConsumer jwtConsumer;

  @Getter
  private JsonWebEncryption jwe;

  @Override
  public void run(T configuration, Environment environment) throws Exception {
    var jwtAuthBundleConfiguration = getJwtAuthBundleConfiguration(configuration);
    key = new AesKey(jwtAuthBundleConfiguration.getKey().getBytes(StandardCharsets.UTF_8));
    jwtConsumer = new JwtConsumerBuilder()
        .setRequireJwtId()
        .setAllowedClockSkewInSeconds(jwtAuthBundleConfiguration.getClockSkew())
        .setDisableRequireSignature()
        .setSkipSignatureVerification()
        .setRequireSubject()
        .setSkipDefaultAudienceValidation()
        .setDecryptionKey(key)
        .build();
    jwe = new JsonWebEncryption();
    jwe.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT,
        KeyManagementAlgorithmIdentifiers.A128KW));
    jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT,
        ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512));
    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
    jwe.setKey(key);
    environment.jersey().register(JwtAuthDynamicFeature.builder()
        .authorizer(authorizer())
            .jwtConsumer(jwtConsumer)
            .cacheExpiry(jwtAuthBundleConfiguration.getCacheExpiry())
            .cacheSize(jwtAuthBundleConfiguration.getCacheMaxSize())
        .build());
    environment.jersey().register(new AuthValueFactoryProvider.Binder<>(JwtUser.class));
    environment.jersey().register(TokenResource.builder().jwe(jwe).build());
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {

  }

  protected JwtAuthBundleConfiguration getJwtAuthBundleConfiguration(T configuration) {
    return new JwtAuthBundleConfiguration();
  }

  protected JwtAuthorizer authorizer() {
    return null;
  }
  public void setKey(final byte[] jwtKey) {
    key = new AesKey(jwtKey);
  }

}
