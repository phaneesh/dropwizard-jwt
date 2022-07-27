package io.dropwizard.auth.jwt.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtAuthBundleConfiguration {

    private String key;

    @Default
    private int cacheExpiry = 3600;

    @Default
    private int cacheMaxSize = 1000;

    @Default
    private int clockSkew = 30;

    @Default
    private String authHeader = "Authorization";
}
