package io.dropwizard.auth.jwt;

import io.dropwizard.auth.jwt.annotation.JwtAuthRequired;
import io.dropwizard.auth.jwt.core.JwtUser;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.internal.inject.AbstractContainerRequestValueFactory;
import org.glassfish.jersey.server.internal.inject.AbstractValueFactoryProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.internal.inject.ParamInjectionResolver;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Inject;
import javax.inject.Singleton;

@Singleton
public class JwtAuthValueFactoryProvider extends AbstractValueFactoryProvider {

    @Inject
    public JwtAuthValueFactoryProvider(MultivaluedParameterExtractorProvider multivaluedParameterExtractorProvider,
                                       ServiceLocator serviceLocator) {
        super(multivaluedParameterExtractorProvider, serviceLocator, Parameter.Source.UNKNOWN);
    }

    @Override
    protected AbstractContainerRequestValueFactory<?> createValueFactory(Parameter parameter) {
        if (parameter.isAnnotationPresent(JwtAuthRequired.class)) {
            return new AbstractContainerRequestValueFactory<JwtUser>() {
                @Override
                public JwtUser provide() {
                    final Object userObject = getContainerRequest().getProperty("user");
                    if (userObject != null && userObject instanceof JwtUser) {
                        return (JwtUser) userObject;
                    } else {
                        return null;
                    }
                }
            };
        } else {
            return null;
        }
    }

    private static class AuthRequiredInjectionResolver extends ParamInjectionResolver<JwtAuthRequired> {
        public AuthRequiredInjectionResolver() {
            super(JwtAuthValueFactoryProvider.class);
        }
    }

    public static class Binder extends AbstractBinder {
        @Override
        protected void configure() {
            bind(JwtAuthValueFactoryProvider.class).to(ValueFactoryProvider.class).in(Singleton.class);
            bind(AuthRequiredInjectionResolver.class).to(new TypeLiteral<InjectionResolver<JwtAuthRequired>>() {
            }).in(Singleton.class);
        }
    }
}