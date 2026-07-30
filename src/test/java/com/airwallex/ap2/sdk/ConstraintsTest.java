package com.airwallex.ap2.sdk;

import static org.assertj.core.api.Assertions.assertThat;

import com.airwallex.ap2.protocol.AgentRecurrence;
import com.airwallex.ap2.protocol.AllowedMerchants;
import com.airwallex.ap2.protocol.AllowedPayees;
import com.airwallex.ap2.protocol.AllowedPaymentInstruments;
import com.airwallex.ap2.protocol.AllowedPisps;
import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.AmountRange;
import com.airwallex.ap2.protocol.Budget;
import com.airwallex.ap2.protocol.CartLineItem;
import com.airwallex.ap2.protocol.Checkout;
import com.airwallex.ap2.protocol.CheckoutStatus;
import com.airwallex.ap2.protocol.ExecutionDate;
import com.airwallex.ap2.protocol.Frequency;
import com.airwallex.ap2.protocol.Item;
import com.airwallex.ap2.protocol.LineItem;
import com.airwallex.ap2.protocol.LineItemRequirements;
import com.airwallex.ap2.protocol.LineItems;
import com.airwallex.ap2.protocol.Link;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.OpenCheckoutMandate;
import com.airwallex.ap2.protocol.OpenPaymentMandate;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.protocol.PaymentReference;
import com.airwallex.ap2.protocol.Pisp;
import com.airwallex.ap2.protocol.Total;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConstraintsTest {

    // ── Payment constraint evaluators ──────────────────────────────────────

    @Test
    void amountRangePasses() {
        var open = new OpenPaymentMandate(null, List.of(new AmountRange("USD", 5000, null)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).isEmpty();
    }

    @Test
    void amountRangeFailsWhenBelowMinimum() {
        var open = new OpenPaymentMandate(null, List.of(new AmountRange("USD", 5000, 100)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = makePaymentMandate(50, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("below minimum"));
    }

    @Test
    void amountRangeFailsWhenAboveMaximum() {
        var open = new OpenPaymentMandate(null, List.of(new AmountRange("USD", 5000, null)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = makePaymentMandate(6000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("exceeds maximum"));
    }

    @Test
    void amountRangeFailsOnCurrencyMismatch() {
        var open = new OpenPaymentMandate(null, List.of(new AmountRange("EUR", 5000, null)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("Currency mismatch"));
    }

    @Test
    void allowedPayeePasses() {
        var open = new OpenPaymentMandate(null,
                List.of(new AllowedPayees(List.of(new Merchant("m-1", "Shop", null)))), Map.of(), null, null, null, null,
                null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).isEmpty();
    }

    @Test
    void allowedPayeeFailsForUnknownMerchant() {
        var open = new OpenPaymentMandate(null,
                List.of(new AllowedPayees(List.of(new Merchant("other", "Other", null)))), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("not in allowed list"));
    }

    @Test
    void paymentReferencePassesWithMatchingHash() {
        var open = new OpenPaymentMandate(null, List.of(new PaymentReference("abc123")), Map.of(), null, null, null, null,
                null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, "abc123", null);
        assertThat(violations).isEmpty();
    }

    @Test
    void paymentReferenceFailsOnMismatch() {
        var open = new OpenPaymentMandate(null, List.of(new PaymentReference("abc123")), Map.of(), null, null, null, null,
                null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, "wrong", null);
        assertThat(violations).anyMatch(v -> v.contains("PaymentReference mismatch"));
    }

    @Test
    void paymentReferenceRequiresOpenCheckoutHash() {
        var open = new OpenPaymentMandate(null, List.of(new PaymentReference("abc123")), Map.of(), null, null, null, null,
                null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("open_checkout_hash is required"));
    }

    @Test
    void agentRecurrenceFailsWhenExceedsMaxOccurrences() {
        var open = new OpenPaymentMandate(null,
                List.of(new AmountRange("USD", 5000, null), new Budget(100.0, "USD"),
                        new AgentRecurrence(Frequency.DAILY, 3)),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var ctx = new Constraints.MandateContext(0, 3, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, ctx);
        assertThat(violations).anyMatch(v -> v.contains("Maximum occurrences exceeded"));
    }

    @Test
    void agentRecurrenceRequiresAmountRange() {
        var open = new OpenPaymentMandate(null,
                List.of(new AgentRecurrence(Frequency.DAILY, 10), new Budget(100.0, "USD")),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("requires payment.amount_range"));
    }

    @Test
    void agentRecurrenceRequiresBudget() {
        var open = new OpenPaymentMandate(null,
                List.of(new AgentRecurrence(Frequency.DAILY, 10), new AmountRange("USD", 5000, null)),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("requires payment.budget"));
    }

    @Test
    void allowedPaymentInstrumentPasses() {
        var open = new OpenPaymentMandate(null,
                List.of(new AllowedPaymentInstruments(List.of(new PaymentInstrument("card-1", "card", null)))),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).isEmpty();
    }

    @Test
    void allowedPaymentInstrumentFails() {
        var open = new OpenPaymentMandate(null,
                List.of(new AllowedPaymentInstruments(List.of(new PaymentInstrument("other", "card", null)))),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("not in allowed list"));
    }

    @Test
    void allowedPispPasses() {
        var pisp = new Pisp("Acme", "Acme Pay", "acme.example.com");
        var open = new OpenPaymentMandate(null, List.of(new AllowedPisps(List.of(pisp))), Map.of(), null, null, null, null,
                null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), pisp, null, null, null, null,
                null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).isEmpty();
    }

    @Test
    void allowedPispFails() {
        var open = new OpenPaymentMandate(null, List.of(new AllowedPisps(
                List.of(new Pisp("Other", "Other", "other.example.com")))),
                Map.of(), null, null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null),
                new Pisp("Acme", "Acme Pay", "acme.example.com"), null, null, null, null, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("not in allowed list"));
    }

    @Test
    void budgetPasses() {
        var open = new OpenPaymentMandate(null, List.of(new Budget(50.0, "USD")), Map.of(), null, null, null, null, null,
                null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var ctx = new Constraints.MandateContext(0, 0, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, ctx);
        assertThat(violations).isEmpty();
    }

    @Test
    void budgetFailsWhenExceeded() {
        var open = new OpenPaymentMandate(null, List.of(new Budget(10.0, "USD")), Map.of(), null, null, null, null, null,
                null, null, null);
        var closed = makePaymentMandate(1000, "USD");
        var ctx = new Constraints.MandateContext(500, 0, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, ctx);
        assertThat(violations).anyMatch(v -> v.contains("exceeds budget limit"));
    }

    @Test
    void executionDatePasses() {
        var open = new OpenPaymentMandate(null, List.of(new ExecutionDate("2025-01-01", "2025-12-31")), Map.of(), null,
                null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, "2025-06-15", null, null,
                null, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).isEmpty();
    }

    @Test
    void executionDateFailsBeforeWindow() {
        var open = new OpenPaymentMandate(null, List.of(new ExecutionDate("2025-06-01", null)), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, "2025-01-01", null, null,
                null, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("before allowed window"));
    }

    @Test
    void executionDateFailsAfterWindow() {
        var open = new OpenPaymentMandate(null, List.of(new ExecutionDate(null, "2025-06-01")), Map.of(), null, null, null,
                null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, "2025-12-31", null, null,
                null, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("after allowed window"));
    }

    @Test
    void presetPaymentClaimsDetectsPayeeMismatch() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(),
                new Merchant("m-1", "Shop", null), null, null, null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-2", "Other", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null,
                null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("Pre-set payee mismatch"));
    }

    @Test
    void presetPaymentClaimsDetectsAmountMismatch() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, new Amount(2000, "USD"), null, null, null, null,
                null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null,
                null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("Pre-set amount mismatch"));
    }

    @Test
    void presetPaymentClaimsDetectsPaymentInstrumentMismatch() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, null,
                new PaymentInstrument("card-2", "card", null), null, null, null, null, null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null,
                null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("Pre-set payment_instrument mismatch"));
    }

    @Test
    void presetPaymentClaimsDetectsExecutionDateMismatch() {
        var open = new OpenPaymentMandate(null, List.of(), Map.of(), null, null, null, null, "2025-06-01", null, null,
                null);
        var closed = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, "2025-12-31", null, null,
                null, null);
        var violations = Constraints.checkPaymentConstraints(open, closed, null, null);
        assertThat(violations).anyMatch(v -> v.contains("Pre-set execution_date mismatch"));
    }

    // ── Checkout constraint evaluators ────────────────────────────────────

    @Test
    void allowedMerchantsPasses() {
        var open = new OpenCheckoutMandate(null,
                List.of(new AllowedMerchants(List.of(new Merchant("m-1", "Shop", null)))), Map.of(), null, null);
        var checkout = makeCheckout(new Merchant("m-1", "Shop", null));
        var violations = Constraints.checkCheckoutConstraints(open, checkout);
        assertThat(violations).isEmpty();
    }

    @Test
    void allowedMerchantsFails() {
        var open = new OpenCheckoutMandate(null,
                List.of(new AllowedMerchants(List.of(new Merchant("other", "Other", null)))), Map.of(), null, null);
        var checkout = makeCheckout(new Merchant("m-1", "Shop", null));
        var violations = Constraints.checkCheckoutConstraints(open, checkout);
        assertThat(violations).anyMatch(v -> v.contains("not in allowed list"));
    }

    @Test
    void lineItemsPasses() {
        var requirement = new LineItemRequirements("req-1",
                List.of(new LineItem("SKU-A", "Widget A")), 1);
        var open = new OpenCheckoutMandate(null, List.of(new LineItems(List.of(requirement))), Map.of(), null, null);
        var checkout = makeCheckout(new Merchant("m-1", "Shop", null),
                new CartLineItem("li-1", new Item("SKU-A", "Widget A", 10, null), 1, List.of(), null));
        var violations = Constraints.checkCheckoutConstraints(open, checkout);
        assertThat(violations).isEmpty();
    }

    @Test
    void lineItemsFailsForUnknownItem() {
        var requirement = new LineItemRequirements("req-1",
                List.of(new LineItem("SKU-A", "Widget A")), 1);
        var open = new OpenCheckoutMandate(null, List.of(new LineItems(List.of(requirement))), Map.of(), null, null);
        var checkout = makeCheckout(new Merchant("m-1", "Shop", null),
                new CartLineItem("li-1", new Item("SKU-B", "Widget B", 10, null), 1, List.of(), null));
        var violations = Constraints.checkCheckoutConstraints(open, checkout);
        assertThat(violations).isNotEmpty();
    }

    @Test
    void lineItemsFailsForEmptyCart() {
        var requirement = new LineItemRequirements("req-1",
                List.of(new LineItem("SKU-A", "Widget A")), 1);
        var open = new OpenCheckoutMandate(null, List.of(new LineItems(List.of(requirement))), Map.of(), null, null);
        var checkout = new Checkout("chk-1", null, List.of(), CheckoutStatus.incomplete, "USD", List.of(), List.of(),
                null, null, null, null);
        var violations = Constraints.checkCheckoutConstraints(open, checkout);
        assertThat(violations).anyMatch(v -> v.contains("Empty cart"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private PaymentMandate makePaymentMandate(int amountCents, String currency) {
        return new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null),
                new Amount(amountCents, currency), new PaymentInstrument("card-1", "card", null), null, null, null, null,
                null, null);
    }

    private Checkout makeCheckout(Merchant merchant, CartLineItem... lineItems) {
        return new Checkout("chk-1", merchant, List.of(lineItems), CheckoutStatus.incomplete, "USD",
                List.of(new Total("subtotal", null, 0), new Total("total", null, 0)),
                List.of(), null, null, null, null);
    }
}