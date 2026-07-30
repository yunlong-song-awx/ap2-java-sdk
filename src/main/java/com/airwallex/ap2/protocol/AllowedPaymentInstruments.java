package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AllowedPaymentInstruments(String type, List<PaymentInstrument> allowed) {
    public static final String TYPE = "payment.allowed_payment_instruments";
    public AllowedPaymentInstruments { if (type == null) type = TYPE; }
    public AllowedPaymentInstruments(List<PaymentInstrument> allowed) { this(TYPE, allowed); }
}