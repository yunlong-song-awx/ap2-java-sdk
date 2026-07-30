package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "status")
@JsonSubTypes({
    @JsonSubTypes.Type(value = CheckoutReceipt.Success.class, name = "Success"),
    @JsonSubTypes.Type(value = CheckoutReceipt.Error.class, name = "Error")
})
public sealed interface CheckoutReceipt permits CheckoutReceipt.Success, CheckoutReceipt.Error {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    record Success(
        String status,
        String iss,
        long iat,
        String reference,
        String error,
        String errorDescription,
        String orderId) implements CheckoutReceipt {
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
        String orderId) implements CheckoutReceipt {
        public Error { status = "Error"; }
    }
}