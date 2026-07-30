package com.airwallex.ap2;

import com.airwallex.ap2.protocol.CheckoutReceipt;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.protocol.PaymentReceipt;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReceiptClient {
    private static final Logger logger = LoggerFactory.getLogger(ReceiptClient.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private Map<String, Object> createBaseReceipt(String status, String issuer, String reference) {
        Map<String, Object> base = new HashMap<>();
        base.put("status", status);
        base.put("iss", issuer);
        base.put("iat", Instant.now().getEpochSecond());
        base.put("reference", reference);
        return base;
    }

    public PaymentReceipt createPaymentReceipt(PaymentMandate paymentMandateContent, String reference) {
        String paymentId = UUID.randomUUID().toString();
        String issuer = paymentMandateContent.pisp() != null
                ? paymentMandateContent.pisp().domainName() : "";
        Map<String, Object> base = createBaseReceipt("Success", issuer, reference);
        return new PaymentReceipt.Success(
                "Success",
                issuer,
                (long) base.get("iat"),
                reference,
                null,
                null,
                paymentId,
                paymentId,
                paymentId);
    }

    public CheckoutReceipt createCheckoutReceipt(String merchant, String reference, String orderId) {
        Map<String, Object> base = createBaseReceipt("Success", merchant, reference);
        return new CheckoutReceipt.Success(
                "Success",
                merchant,
                (long) base.get("iat"),
                reference,
                null,
                null,
                orderId);
    }

    public Map<String, Object> verifyReceipt(String receiptJwt, ECPublicKey receiptIssuerPublicKey,
            Function<String, Boolean> hasReferenceInStoreCb, boolean isPaymentReceipt) {
        logger.info("verify_receipt called: is_payment_receipt={}", isPaymentReceipt);
        try {
            Map<String, Object> payload = JwtHelper.verifyJwt(receiptJwt, receiptIssuerPublicKey);
            if (isPaymentReceipt) {
                mapper.convertValue(payload, PaymentReceipt.Success.class);
            } else {
                mapper.convertValue(payload, CheckoutReceipt.Success.class);
            }
            String receiptReference = (String) payload.get("reference");
            if (hasReferenceInStoreCb != null && !hasReferenceInStoreCb.apply(receiptReference)) {
                logger.warn("Receipt reference not found in store: {}", receiptReference);
                return Map.of("error", "receipt_reference_not_found_in_store",
                        "message", "Receipt reference does not match any known closed mandate for "
                                + (isPaymentReceipt ? "payment" : "checkout"));
            }
            logger.info("Receipt verified successfully");
            return Map.of("verified", true);
        } catch (Exception e) {
            logger.warn("receipt verification failed: {}", e.getMessage());
            return Map.of("error", "verification_failed",
                    "message", "JWT verification failed: " + e.getMessage());
        }
    }
}