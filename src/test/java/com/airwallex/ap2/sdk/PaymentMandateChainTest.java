package com.airwallex.ap2.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.AmountRange;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.OpenPaymentMandate;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PaymentMandateChainTest {

    @Test
    void parseRequiresExactlyTwoPayloads() {
        assertThatThrownBy(() -> PaymentMandateChain.parse(List.of(Map.of("vct", "mandate.payment.open.1"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("exactly 2 payloads");
    }

    @Test
    void parseReturnsValidChain() {
        var openPayload = Map.<String, Object>of(
                "vct", "mandate.payment.open.1",
                "constraints", List.of(),
                "cnf", Map.of());
        var closedPayload = Map.<String, Object>of(
                "vct", "mandate.payment.1",
                "transaction_id", "txn-1",
                "payee", Map.of("id", "m-1", "name", "Shop"),
                "payment_amount", Map.of("amount", 1000, "currency", "USD"),
                "payment_instrument", Map.of("id", "card-1", "type", "card"));
        var chain = PaymentMandateChain.parse(List.of(openPayload, closedPayload));
        assertThat(chain.openMandate().vct()).isEqualTo("mandate.payment.open.1");
        assertThat(chain.closedMandate().transactionId()).isEqualTo("txn-1");
    }

    @Test
    void verifyPassesWithMatchingTransactionId() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
        var chain = new PaymentMandateChain(open, closed);
        var violations = chain.verify("txn-1");
        assertThat(violations).isEmpty();
    }

    @Test
    void verifyFailsOnTransactionIdMismatch() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
        var chain = new PaymentMandateChain(open, closed);
        var violations = chain.verify("txn-2");
        assertThat(violations).anyMatch(v -> v.contains("transaction_id mismatch"));
    }

    @Test
    void verifyAllowsNullTransactionId() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
        var chain = new PaymentMandateChain(open, closed);
        assertThat(chain.verify((String) null)).isEmpty();
    }

    @Test
    void verifyRunsConstraints() {
        var open = new OpenPaymentMandate(null, List.of(new AmountRange("USD", 500, null)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
        var chain = new PaymentMandateChain(open, closed);
        var violations = chain.verify(null, null, null);
        assertThat(violations).anyMatch(v -> v.contains("exceeds maximum"));
    }
}