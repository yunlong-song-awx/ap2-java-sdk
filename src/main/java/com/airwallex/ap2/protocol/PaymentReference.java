package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record PaymentReference(String type, String conditionalTransactionId) {
    public static final String TYPE = "payment.reference";
    public PaymentReference { if (type == null) type = TYPE; }
    public PaymentReference(String conditionalTransactionId) { this(TYPE, conditionalTransactionId); }
}