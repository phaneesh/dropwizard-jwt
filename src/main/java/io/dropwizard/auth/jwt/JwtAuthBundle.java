package io.dropwizard.auth.jwt;

import com.google.common.base.Preconditions;
import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.auth.jwt.config.JwtAuthBundleConfiguration;
import io.dropwizard.auth.jwt.resources.TokenResource;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.jose4j.keys.AesKey;

import java.security.Key;

public abstract class JwtAuthBundle<T extends Configuration> implements ConfiguredBundle<T> {

    private static Key key;

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        final JwtAuthBundleConfiguration jwtAuthBundleConfiguration = getJwtAuthBundleConfiguration(configuration);
        environment.jersey().register(JwtAuthDynamicFeature.builder()
                .authorizer(authorizer())
                .configuration(jwtAuthBundleConfiguration)
                .build());
        environment.jersey().register(new JwtAuthValueFactoryProvider.Binder());
        environment.jersey().register(new TokenResource());
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

    public static Key getKey() {
        Preconditions.checkNotNull(key, "JWT Key not set");
        return key;
    }

    public void setKey(final byte[] jwtKey) {
        key = new AesKey(jwtKey);
    }

}
