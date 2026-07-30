package com.airwallex.ap2;

import static org.assertj.core.api.Assertions.assertThat;

import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutReceipt;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.protocol.PaymentReceipt;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ReceiptClientTest {

    private final ReceiptClient client = new ReceiptClient();
    private final ECKey signingKey;

    {
        try {
            signingKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PaymentMandate paymentMandate() {
        return new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
    }

    private static Map<String, Object> map(String k1, Object v1, String k2, Object v2, String k3, Object v3,
            String k4, Object v4, String k5, Object v5, String k6, Object v6, String k7, Object v7) {
        var m = new HashMap<String, Object>();
        m.put(k1, v1);
        m.put(k2, v2);
        m.put(k3, v3);
        m.put(k4, v4);
        m.put(k5, v5);
        m.put(k6, v6);
        m.put(k7, v7);
        return m;
    }

    @Test
    void createPaymentReceiptReturnsSuccess() {
        var receipt = client.createPaymentReceipt(paymentMandate(), "ref-123");
        assertThat(receipt).isInstanceOf(PaymentReceipt.Success.class);
        var success = (PaymentReceipt.Success) receipt;
        assertThat(success.status()).isEqualTo("Success");
        assertThat(success.reference()).isEqualTo("ref-123");
        assertThat(success.paymentId()).isNotEmpty();
    }

    @Test
    void createCheckoutReceiptReturnsSuccess() {
        var receipt = client.createCheckoutReceipt("merchant.example.com", "ref-456", "order-1");
        assertThat(receipt).isInstanceOf(CheckoutReceipt.Success.class);
        var success = (CheckoutReceipt.Success) receipt;
        assertThat(success.status()).isEqualTo("Success");
        assertThat(success.reference()).isEqualTo("ref-456");
        assertThat(success.orderId()).isEqualTo("order-1");
    }

    @Test
    void verifyReceiptWithValidSignatureAndReference() throws Exception {
        var payload = map(
                "status", "Success",
                "iss", "test.example.com",
                "iat", System.currentTimeMillis() / 1000,
                "reference", "ref-789",
                "payment_id", "pay-1",
                "psp_confirmation_id", "pay-1",
                "network_confirmation_id", "pay-1");
        var jwt = JwtHelper.createJwt(payload, signingKey.toECPrivateKey());
        var result = client.verifyReceipt(jwt, signingKey.toECPublicKey(),
                ref -> "ref-789".equals(ref), true);
        assertThat(result).containsEntry("verified", true);
    }

    @Test
    void verifyReceiptFailsOnMissingReference() throws Exception {
        var payload = map(
                "status", "Success",
                "iss", "test.example.com",
                "iat", System.currentTimeMillis() / 1000,
                "reference", "ref-missing",
                "payment_id", "pay-2",
                "psp_confirmation_id", "pay-2",
                "network_confirmation_id", "pay-2");
        var jwt = JwtHelper.createJwt(payload, signingKey.toECPrivateKey());
        var result = client.verifyReceipt(jwt, signingKey.toECPublicKey(),
                ref -> false, true);
        assertThat(result).containsEntry("error", "receipt_reference_not_found_in_store");
    }

    @Test
    void verifyReceiptFailsOnWrongSignature() throws Exception {
        var wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        var payload = map(
                "status", "Success",
                "iss", "test.example.com",
                "iat", System.currentTimeMillis() / 1000,
                "reference", "ref-xyz",
                "payment_id", "pay-3",
                "psp_confirmation_id", "pay-3",
                "network_confirmation_id", "pay-3");
        var jwt = JwtHelper.createJwt(payload, signingKey.toECPrivateKey());
        var result = client.verifyReceipt(jwt, wrongKey.toECPublicKey(),
                ref -> true, true);
        assertThat(result).containsEntry("error", "verification_failed");
    }
}