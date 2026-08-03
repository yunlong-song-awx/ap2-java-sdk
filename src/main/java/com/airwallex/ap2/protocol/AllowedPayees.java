package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AllowedPayees(String type, List<Merchant> allowed) {
    public static final String TYPE = "payment.allowed_payees";
    public AllowedPayees { if (type == null) type = TYPE; }
    public AllowedPayees(List<Merchant> allowed) { this(TYPE, allowed); }
}