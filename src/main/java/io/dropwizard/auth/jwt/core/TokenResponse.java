package io.dropwizard.auth.jwt.core;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenResponse {

    private String token;
}
