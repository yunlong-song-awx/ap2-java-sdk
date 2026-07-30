package com.airwallex.ap2.sdk;

import com.airwallex.ap2.CryptoUtils;
import com.airwallex.ap2.protocol.Checkout;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.OpenCheckoutMandate;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public record CheckoutMandateChain(OpenCheckoutMandate openMandate, CheckoutMandate closedMandate) {
    private static final int CHECKOUT_CHAIN_LEN = 2;
    private static final int JWT_COMPACT_PARTS = 3;
    private static final ObjectMapper mapper = new ObjectMapper();

    public static CheckoutMandateChain parse(List<Map<String, Object>> payloads) {
        if (payloads.size() != CHECKOUT_CHAIN_LEN) {
            throw new IllegalArgumentException(
                    "Checkout mandate chain requires exactly 2 payloads, got " + payloads.size());
        }
        return new CheckoutMandateChain(
                mapper.convertValue(payloads.get(0), OpenCheckoutMandate.class),
                mapper.convertValue(payloads.get(1), CheckoutMandate.class));
    }

    public List<String> verify(String expectedCheckoutHash, String checkoutJwt) {
        List<String> violations = new ArrayList<>();
        if (checkoutJwt == null || checkoutJwt.isEmpty()) {
            violations.add("checkout_jwt is required to verify checkout constraints.");
            return violations;
        }
        try {
            Checkout checkout = extractParsedCheckoutObject(checkoutJwt);
            violations.addAll(Constraints.checkCheckoutConstraints(openMandate, checkout));
        } catch (Exception e) {
            violations.add(e.getMessage());
            return violations;
        }
        if (expectedCheckoutHash != null && !expectedCheckoutHash.equals(closedMandate.checkoutHash())) {
            violations.add("Checkout checkout_hash mismatch: expected "
                    + expectedCheckoutHash + ", got " + closedMandate.checkoutHash());
        }
        return violations;
    }

    public Checkout extractParsedCheckoutObject(String checkoutJwt) {
        String[] parts = checkoutJwt.split("\\.");
        if (parts.length != JWT_COMPACT_PARTS) {
            throw new IllegalArgumentException("Malformed checkout_jwt: expected header.payload.signature");
        }
        try {
            byte[] decodedBytes = CryptoUtils.b64urlDecode(parts[1]);
            return mapper.readValue(decodedBytes, Checkout.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode checkout_jwt: " + e.getMessage(), e);
        }
    }
}