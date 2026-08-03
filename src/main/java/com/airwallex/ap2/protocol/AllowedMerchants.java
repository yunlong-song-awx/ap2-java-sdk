package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AllowedMerchants(String type, List<Merchant> allowed) {
    public static final String TYPE = "checkout.allowed_merchants";
    public AllowedMerchants { if (type == null) type = TYPE; }
    public AllowedMerchants(List<Merchant> allowed) { this(TYPE, allowed); }
}