package io.dropwizard.auth.jwt.core;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@Builder
public class TokenRequest {

    private String subject;

    private List<String> audience;

    private Map<String, Object> claims;

    private Date expiresOn;
}
