package io.dropwizard.auth.jwt.config;

import lombok.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

/**
 * @author phaneesh
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtAuthBundleConfiguration {

    private String key;

    private int cacheExpiry = 3600;

    private int cacheMaxSize = 1000;

    private int clockSkew = 30;
}
