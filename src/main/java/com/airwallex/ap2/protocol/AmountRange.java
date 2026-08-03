package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AmountRange(String type, String currency, int max, Integer min) {
    public static final String TYPE = "payment.amount_range";
    public AmountRange { if (type == null) type = TYPE; }
    public AmountRange(String currency, int max, Integer min) { this(TYPE, currency, max, min); }
}