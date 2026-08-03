package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Buyer(
    String firstName,
    String lastName,
    String email,
    String phoneNumber) {
}