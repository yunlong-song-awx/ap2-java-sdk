package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "status")
@JsonSubTypes({
    @JsonSubTypes.Type(value = PaymentReceipt.Success.class, name = "Success"),
    @JsonSubTypes.Type(value = PaymentReceipt.Error.class, name = "Error")
})
public sealed interface PaymentReceipt permits PaymentReceipt.Success, PaymentReceipt.Error {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    record Success(
        String status,
        String iss,
        long iat,
        String reference,
        String error,
        String errorDescription,
        String paymentId,
        String pspConfirmationId,
        String networkConfirmationId) implements PaymentReceipt {
        public Success { status = "Success"; }
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    record Error(
        String status,
        String iss,
        long iat,
        String reference,
        String error,
        String errorDescription,
        String paymentId,
        String pspConfirmationId,
        String networkConfirmationId) implements PaymentReceipt {
        public Error { status = "Error"; }
    }
}