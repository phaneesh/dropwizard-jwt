package io.dropwizard.auth.jwt;

import io.dropwizard.auth.jwt.core.JwtUser;
import org.glassfish.jersey.server.ContainerRequest;

import java.security.Principal;

class PrincipalContainerRequestValueFactory {
  private final ContainerRequest request;

  public PrincipalContainerRequestValueFactory(ContainerRequest request) {
    this.request = request;
  }

  /**
   * @return {@link io.dropwizard.auth.jwt.core.JwtUser} stored on the request, or {@code null}
   *         if no object was found.
   */
  public JwtUser provide() {
    final Principal principal = request.getSecurityContext().getUserPrincipal();
    if (principal == null) {
      throw new IllegalStateException("Cannot inject a custom principal into unauthenticated request");
    }
    return (JwtUser) principal;
  }
}

