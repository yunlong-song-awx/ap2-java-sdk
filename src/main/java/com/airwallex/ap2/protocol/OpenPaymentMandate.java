package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;
import java.util.Map;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record OpenPaymentMandate(
    String vct,
    List<Object> constraints,
    Map<String, Object> cnf,
    Merchant payee,
    Amount paymentAmount,
    PaymentInstrument paymentInstrument,
    Pisp pisp,
    String executionDate,
    Map<String, Object> riskData,
    Long iat,
    Long exp) {
    public static final String VCT = "mandate.payment.open.1";
    public OpenPaymentMandate { if (vct == null) vct = VCT; }
}