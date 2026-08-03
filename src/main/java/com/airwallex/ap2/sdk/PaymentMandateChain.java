package com.airwallex.ap2.sdk;

import com.airwallex.ap2.protocol.OpenPaymentMandate;
import com.airwallex.ap2.protocol.PaymentMandate;
import java.util.List;
import java.util.Map;

public record PaymentMandateChain(OpenPaymentMandate openMandate, PaymentMandate closedMandate) {
    private static final int PAYMENT_CHAIN_LEN = 2;

    public static PaymentMandateChain parse(List<Map<String, Object>> payloads) {
        if (payloads.size() != PAYMENT_CHAIN_LEN) {
            throw new IllegalArgumentException(
                    "Payment mandate chain requires exactly 2 payloads, got " + payloads.size());
        }
        return new PaymentMandateChain(
                Constraints.MAPPER.convertValue(payloads.get(0), OpenPaymentMandate.class),
                Constraints.MAPPER.convertValue(payloads.get(1), PaymentMandate.class));
    }

    public List<String> verify(String expectedTransactionId, String expectedOpenCheckoutHash,
            Constraints.MandateContext mandateContext) {
        List<String> violations = Constraints.checkPaymentConstraints(
                openMandate, closedMandate, expectedOpenCheckoutHash, mandateContext);
        if (expectedTransactionId != null && !expectedTransactionId.equals(closedMandate.transactionId())) {
            violations.add("Payment transaction_id mismatch: expected "
                    + expectedTransactionId + ", got " + closedMandate.transactionId());
        }
        return violations;
    }

    public List<String> verify(String expectedTransactionId) {
        return verify(expectedTransactionId, null, null);
    }
}