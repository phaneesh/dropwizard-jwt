package io.dropwizard.auth.jwt;

import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.jwt.annotation.JwtAuthRequired;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.internal.inject.AbstractValueParamProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueParamProvider;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.security.Principal;
import java.util.function.Function;

public class JwtUserValueFactoryProvider <T extends Principal> extends AbstractValueParamProvider {

  /**
   * Class of the provided {@link Principal}
   */
  private final Class<T> principalClass;

  /**
   * {@link Principal} value factory provider injection constructor.
   *
   * @param mpep                   multivalued parameter extractor provider
   * @param principalClassProvider provider of the principal class
   */
  @Inject
  public JwtUserValueFactoryProvider(MultivaluedParameterExtractorProvider mpep, JwtUserValueFactoryProvider.PrincipalClassProvider<T> principalClassProvider) {
    super(() -> mpep, org.glassfish.jersey.model.Parameter.Source.UNKNOWN);
    this.principalClass = principalClassProvider.clazz;
  }

  @Nullable
  @Override
  protected Function<ContainerRequest, ?> createValueProvider(Parameter parameter) {
    if (!parameter.isAnnotationPresent(JwtAuthRequired.class)) {
      return null;
    } else if (principalClass.equals(parameter.getRawType())) {
      return request -> new PrincipalContainerRequestValueFactory(request).provide();
    }
    return null;
  }

  @Singleton
  static class PrincipalClassProvider<T extends Principal> {

    private final Class<T> clazz;

    PrincipalClassProvider(Class<T> clazz) {
      this.clazz = clazz;
    }
  }

  public static class Binder<T extends Principal> extends AbstractBinder {

    private final Class<T> principalClass;

    public Binder(Class<T> principalClass) {
      this.principalClass = principalClass;
    }

    @Override
    protected void configure() {
      bind(new JwtUserValueFactoryProvider.PrincipalClassProvider<>(principalClass)).to(JwtUserValueFactoryProvider.PrincipalClassProvider.class);
      bind(JwtUserValueFactoryProvider.class).to(ValueParamProvider.class).in(Singleton.class);
    }
  }
}
