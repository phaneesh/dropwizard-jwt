package io.dropwizard.auth.jwt;

import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.auth.jwt.config.JwtAuthConfig;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

public abstract class JwtAuthBundle<T extends Configuration> implements ConfiguredBundle<T> {

    @Override
    public void run(T configuration, Environment environment) throws Exception {

        JwtAuthConfig jwtAuthConfig = getConfig(configuration);
        environment.jersey().register(JwtAuthDynamicFeature.builder()
                .key(jwtAuthConfig.getKey())
                .authorizer(authorizer())
                .build());
        environment.jersey().register(new JwtAuthValueFactoryProvider.Binder());
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {

    }

    protected abstract JwtAuthConfig getConfig(T configuration);

    protected JwtAuthorizer authorizer() {
        return null;
    }

}
