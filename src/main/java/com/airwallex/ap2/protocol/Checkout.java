package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Checkout(
    String id,
    Merchant merchant,
    List<CartLineItem> lineItems,
    CheckoutStatus status,
    String currency,
    List<Total> totals,
    List<Link> links,
    Buyer buyer,
    List<Message> messages,
    String expiresAt,
    String continueUrl) {
}