package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;
import java.util.Map;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record OpenCheckoutMandate(
    String vct,
    List<Object> constraints,
    Map<String, Object> cnf,
    Long iat,
    Long exp) {
    public static final String VCT = "mandate.checkout.open.1";
    public OpenCheckoutMandate { if (vct == null) vct = VCT; }
}