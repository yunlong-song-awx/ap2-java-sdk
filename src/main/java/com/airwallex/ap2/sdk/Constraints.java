package com.airwallex.ap2.sdk;

import com.airwallex.ap2.protocol.AgentRecurrence;
import com.airwallex.ap2.protocol.AllowedMerchants;
import com.airwallex.ap2.protocol.AllowedPayees;
import com.airwallex.ap2.protocol.AllowedPaymentInstruments;
import com.airwallex.ap2.protocol.AllowedPisps;
import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.AmountRange;
import com.airwallex.ap2.protocol.Budget;
import com.airwallex.ap2.protocol.Checkout;
import com.airwallex.ap2.protocol.ExecutionDate;
import com.airwallex.ap2.protocol.Frequency;
import com.airwallex.ap2.protocol.LineItems;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.OpenCheckoutMandate;
import com.airwallex.ap2.protocol.OpenPaymentMandate;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.protocol.PaymentReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

public final class Constraints {

    private Constraints() {}

    public static final ObjectMapper MAPPER = new ObjectMapper();

    public record MandateContext(int totalAmount, int totalUses, Long lastUsedDate) {
        public MandateContext() {
            this(0, 0, null);
        }
    }

    static boolean merchantMatches(Merchant candidate, Merchant target) {
        if (candidate.id() != null && target.id() != null
                && !candidate.id().isEmpty() && !target.id().isEmpty()) {
            return candidate.id().equals(target.id());
        }
        return candidate.name() != null && candidate.name().equals(target.name())
                && candidate.name() != null && !candidate.name().isEmpty()
                && candidate.website() != null && candidate.website().equals(target.website())
                && candidate.website() != null && !candidate.website().isEmpty();
    }

    // ── Payment constraint evaluators ──────────────────────────────────────

    private interface PaymentConstraintEvaluator {
        List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash);
    }

    private record AmountRangeEvaluator(AmountRange constraint) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            List<String> violations = new ArrayList<>();
            Amount amount = closedMandate.paymentAmount();
            if (constraint.currency() != null && !constraint.currency().equals(amount.currency())) {
                violations.add("Currency mismatch: expected " + constraint.currency()
                        + ", got " + amount.currency());
            }
            if (constraint.min() != null && amount.amount() < constraint.min()) {
                violations.add("Amount " + amount.amount() + " below minimum " + constraint.min());
            }
            if (amount.amount() > constraint.max()) {
                violations.add("Amount " + amount.amount() + " exceeds maximum " + constraint.max());
            }
            return violations;
        }
    }

    private record AllowedPayeeEvaluator(AllowedPayees constraint) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            Merchant payee = closedMandate.payee();
            for (Merchant allowed : constraint.allowed()) {
                if (merchantMatches(allowed, payee)) return List.of();
            }
            return List.of("Payee " + payee.name() + " not in allowed list");
        }
    }

    private record PaymentReferenceEvaluator(PaymentReference constraint) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            if (openCheckoutHash == null) {
                return List.of("open_checkout_hash is required to evaluate PaymentReference constraints");
            }
            if (!openCheckoutHash.equals(constraint.conditionalTransactionId())) {
                return List.of("PaymentReference mismatch: expected open checkout hash "
                        + constraint.conditionalTransactionId() + ", got " + openCheckoutHash);
            }
            return List.of();
        }
    }

    private record AgentRecurrenceEvaluator(AgentRecurrence constraint, MandateContext mandateContext)
            implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            List<String> violations = new ArrayList<>();
            Integer limit = constraint.maxOccurrences();
            if (limit != null) {
                if (mandateContext == null) {
                    return List.of("Missing mandate context required to evaluate recurrence");
                }
                int occurrenceCount = mandateContext.totalUses();
                if (occurrenceCount >= limit) {
                    violations.add("Maximum occurrences exceeded: " + occurrenceCount + " >= " + limit);
                }
            }
            return violations;
        }
    }

    private record AllowedPaymentInstrumentEvaluator(AllowedPaymentInstruments constraint)
            implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            var instrument = closedMandate.paymentInstrument();
            if (instrument == null) return List.of("Missing payment instrument in closed mandate");
            for (var allowed : constraint.allowed()) {
                if (allowed.id().equals(instrument.id())) return List.of();
            }
            return List.of("Payment instrument " + instrument.id() + " not in allowed list");
        }
    }

    private record AllowedPispEvaluator(AllowedPisps constraint) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            if (closedMandate.pisp() == null) return List.of("Missing PISP in closed mandate");
            for (var allowed : constraint.allowed()) {
                if (allowed.domainName().equals(closedMandate.pisp().domainName())
                        && allowed.legalName().equals(closedMandate.pisp().legalName())
                        && allowed.brandName().equals(closedMandate.pisp().brandName())) {
                    return List.of();
                }
            }
            return List.of("PISP " + closedMandate.pisp() + " not in allowed list");
        }
    }

    private record BudgetEvaluator(Budget constraint, MandateContext mandateContext) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            if (!closedMandate.paymentAmount().currency().equals(constraint.currency())) {
                return List.of("Budget currency mismatch: expected " + constraint.currency()
                        + ", got " + closedMandate.paymentAmount().currency());
            }
            if (mandateContext == null) return List.of("Missing mandate context required to evaluate budget");
            int pastSpend = mandateContext.totalAmount();
            int totalSpend = (int) (pastSpend + closedMandate.paymentAmount().amount());
            int budgetMaxCents = (int) (constraint.max() * 100);
            if (totalSpend > budgetMaxCents) {
                return List.of("Cumulative spend " + totalSpend + " exceeds budget limit "
                        + budgetMaxCents + " (past spend: " + pastSpend + ")");
            }
            return List.of();
        }
    }

    private record ExecutionDateEvaluator(ExecutionDate constraint) implements PaymentConstraintEvaluator {
        @Override
        public List<String> evaluate(PaymentMandate closedMandate, String openCheckoutHash) {
            String execDate = closedMandate.executionDate();
            if (execDate == null) return List.of();
            List<String> violations = new ArrayList<>();
            if (constraint.notBefore() != null && execDate.compareTo(constraint.notBefore()) < 0) {
                violations.add("Execution date " + execDate + " is before allowed window "
                        + constraint.notBefore());
            }
            if (constraint.notAfter() != null && execDate.compareTo(constraint.notAfter()) > 0) {
                violations.add("Execution date " + execDate + " is after allowed window "
                        + constraint.notAfter());
            }
            return violations;
        }
    }

    private static PaymentConstraintEvaluator createPaymentEvaluator(
            Object constraint, MandateContext mandateContext) {
        if (constraint instanceof AmountRange c) return new AmountRangeEvaluator(c);
        if (constraint instanceof AllowedPayees c) return new AllowedPayeeEvaluator(c);
        if (constraint instanceof PaymentReference c) return new PaymentReferenceEvaluator(c);
        if (constraint instanceof AgentRecurrence c) return new AgentRecurrenceEvaluator(c, mandateContext);
        if (constraint instanceof AllowedPaymentInstruments c) return new AllowedPaymentInstrumentEvaluator(c);
        if (constraint instanceof AllowedPisps c) return new AllowedPispEvaluator(c);
        if (constraint instanceof Budget c) return new BudgetEvaluator(c, mandateContext);
        if (constraint instanceof ExecutionDate c) return new ExecutionDateEvaluator(c);
        throw new IllegalArgumentException("Unknown payment constraint type: " + constraint.getClass());
    }

    // ── Checkout constraint evaluators ─────────────────────────────────────

    private interface CheckoutConstraintEvaluator {
        List<String> evaluate(Checkout checkout);
    }

    private record AllowedMerchantsEvaluator(AllowedMerchants constraint) implements CheckoutConstraintEvaluator {
        @Override
        public List<String> evaluate(Checkout checkout) {
            Merchant merchantData = checkout.merchant();
            if (merchantData == null) return List.of("Missing merchant in checkout");
            for (Merchant allowed : constraint.allowed()) {
                if (merchantMatches(allowed, merchantData)) return List.of();
            }
            return List.of("Merchant " + (merchantData.name() != null ? merchantData.name() : "") + " not in allowed list");
        }
    }

    private record LineItemsEvaluator(LineItems constraint) implements CheckoutConstraintEvaluator {
        @Override
        public List<String> evaluate(Checkout checkout) {
            var checkoutItems = checkout.lineItems();
            if (checkoutItems == null || checkoutItems.isEmpty()) {
                return List.of("Empty cart does not satisfy line_items constraint");
            }
            return MaxFlowHelper.evaluateLineItemsMaxFlow(checkoutItems, constraint.items());
        }
    }

    private static CheckoutConstraintEvaluator createCheckoutEvaluator(Object constraint) {
        if (constraint instanceof AllowedMerchants c) return new AllowedMerchantsEvaluator(c);
        if (constraint instanceof LineItems c) return new LineItemsEvaluator(c);
        throw new IllegalArgumentException("Unknown checkout constraint type: " + constraint.getClass());
    }

    // ── Preset claims verification ─────────────────────────────────────────

    private static List<String> checkPresetPaymentClaims(
            OpenPaymentMandate openMandate, PaymentMandate closedMandate) {
        List<String> violations = new ArrayList<>();

        if (openMandate.payee() != null && !merchantMatches(openMandate.payee(), closedMandate.payee())) {
            violations.add("Pre-set payee mismatch: expected " + openMandate.payee().name()
                    + ", got " + closedMandate.payee().name());
        }
        if (openMandate.paymentAmount() != null
                && !openMandate.paymentAmount().equals(closedMandate.paymentAmount())) {
            violations.add("Pre-set amount mismatch: expected " + openMandate.paymentAmount()
                    + ", got " + closedMandate.paymentAmount());
        }
        if (openMandate.paymentInstrument() != null
                && !openMandate.paymentInstrument().equals(closedMandate.paymentInstrument())) {
            violations.add("Pre-set payment_instrument mismatch");
        }
        if (openMandate.executionDate() != null
                && !openMandate.executionDate().equals(closedMandate.executionDate())) {
            violations.add("Pre-set execution_date mismatch: expected " + openMandate.executionDate()
                    + ", got " + closedMandate.executionDate());
        }

        return violations;
    }

    // ── Public API ─────────────────────────────────────────────────────────

    public static List<String> checkPaymentConstraints(
            OpenPaymentMandate openMandate,
            PaymentMandate closedMandate,
            String expectedOpenCheckoutHash,
            MandateContext mandateContext) {
        List<String> violations = new ArrayList<>();
        violations.addAll(checkPresetPaymentClaims(openMandate, closedMandate));

        boolean hasRecurrence = false;
        boolean hasAmount = false;
        boolean hasBudget = false;
        for (Object c : openMandate.constraints()) {
            if (c instanceof AgentRecurrence) hasRecurrence = true;
            if (c instanceof AmountRange) hasAmount = true;
            if (c instanceof Budget) hasBudget = true;
        }
        if (hasRecurrence) {
            if (!hasAmount) {
                violations.add("payment.agent_recurrence requires payment.amount_range constraint");
            }
            if (!hasBudget) {
                violations.add("payment.agent_recurrence requires payment.budget constraint");
            }
        }

        for (Object constraint : openMandate.constraints()) {
            var evaluator = createPaymentEvaluator(constraint, mandateContext);
            violations.addAll(evaluator.evaluate(closedMandate, expectedOpenCheckoutHash));
        }

        return violations;
    }

    public static List<String> checkCheckoutConstraints(
            OpenCheckoutMandate openMandate,
            Checkout checkout) {
        List<String> violations = new ArrayList<>();
        for (Object constraint : openMandate.constraints()) {
            var evaluator = createCheckoutEvaluator(constraint);
            violations.addAll(evaluator.evaluate(checkout));
        }
        return violations;
    }
}