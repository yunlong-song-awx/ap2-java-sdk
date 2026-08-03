package com.airwallex.ap2.extension.ucp;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.nimbusds.jose.jwk.ECKey;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record UcpDiscoveryProfile(List<ECKey> signingKeys) {
}