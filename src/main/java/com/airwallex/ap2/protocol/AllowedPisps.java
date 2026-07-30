package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AllowedPisps(String type, List<Pisp> allowed) {
    public static final String TYPE = "payment.allowed_pisps";
    public AllowedPisps { if (type == null) type = TYPE; }
    public AllowedPisps(List<Pisp> allowed) { this(TYPE, allowed); }
}