package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LineItems(String type, List<LineItemRequirements> items) {
    public static final String TYPE = "checkout.line_items";
    public LineItems { if (type == null) type = TYPE; }
    public LineItems(List<LineItemRequirements> items) { this(TYPE, items); }
}