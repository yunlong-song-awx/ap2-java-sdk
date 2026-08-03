package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Budget(String type, double max, String currency) {
    public static final String TYPE = "payment.budget";
    public Budget { if (type == null) type = TYPE; }
    public Budget(double max, String currency) { this(TYPE, max, currency); }
}