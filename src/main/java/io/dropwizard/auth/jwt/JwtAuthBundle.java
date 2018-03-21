package io.dropwizard.auth.jwt;

import com.google.common.base.Preconditions;
import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.jose4j.keys.AesKey;

import java.security.Key;

public abstract class JwtAuthBundle<T extends Configuration> implements ConfiguredBundle<T> {

    private static Key key;

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        environment.jersey().register(JwtAuthDynamicFeature.builder()
                .authorizer(authorizer())
                .build());
        environment.jersey().register(new JwtAuthValueFactoryProvider.Binder());
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {

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
