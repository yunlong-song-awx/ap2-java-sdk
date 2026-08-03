package com.airwallex.ap2.sdk;

import static org.assertj.core.api.Assertions.assertThat;

import com.airwallex.ap2.protocol.CartLineItem;
import com.airwallex.ap2.protocol.Item;
import com.airwallex.ap2.protocol.LineItem;
import com.airwallex.ap2.protocol.LineItemRequirements;
import com.airwallex.ap2.protocol.Total;
import java.util.List;
import org.junit.jupiter.api.Test;

class MaxFlowHelperTest {

    @Test
    void singleItemMatchesSingleRequirement() {
        var items = List.of(lineItem("SKU-A", 1));
        var reqs = List.of(requirement("r1", List.of(constraintItem("SKU-A")), 1));
        assertThat(MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs)).isEmpty();
    }

    @Test
    void failsWhenItemNotInAnyRequirement() {
        var items = List.of(lineItem("SKU-B", 1));
        var reqs = List.of(requirement("r1", List.of(constraintItem("SKU-A")), 1));
        var violations = MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs);
        assertThat(violations).anyMatch(v -> v.contains("not in any requirement"));
    }

    @Test
    void greedyEliminationSatisfiesAll() {
        var items = List.of(lineItem("A", 2), lineItem("B", 1));
        var reqs = List.of(
                requirement("r1", List.of(constraintItem("A")), 2),
                requirement("r2", List.of(constraintItem("B")), 1));
        assertThat(MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs)).isEmpty();
    }

    @Test
    void wildcardRequirementAcceptsAnyItem() {
        var items = List.of(lineItem("A", 3));
        var reqs = List.of(requirement("r1", List.of(), 3));
        assertThat(MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs)).isEmpty();
    }

    @Test
    void complexMatchingRequiresMaxFlow() {
        var items = List.of(lineItem("A", 1), lineItem("B", 1));
        var reqs = List.of(
                requirement("r1", List.of(constraintItem("A"), constraintItem("B")), 1),
                requirement("r2", List.of(constraintItem("A"), constraintItem("B")), 1));
        assertThat(MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs)).isEmpty();
    }

    @Test
    void edmondsKarpModeWorks() {
        var items = List.of(lineItem("A", 1), lineItem("B", 1));
        var reqs = List.of(
                requirement("r1", List.of(constraintItem("A"), constraintItem("B")), 1),
                requirement("r2", List.of(constraintItem("A"), constraintItem("B")), 1));
        assertThat(MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs, "edmonds_karp")).isEmpty();
    }

    @Test
    void unsatisfiedComplexMatchingReturnsViolations() {
        var items = List.of(lineItem("A", 3));
        var reqs = List.of(
                requirement("r1", List.of(constraintItem("A")), 1),
                requirement("r2", List.of(constraintItem("A")), 1));
        var violations = MaxFlowHelper.evaluateLineItemsMaxFlow(items, reqs);
        assertThat(violations).anyMatch(v -> v.contains("Cannot satisfy line item constraints"));
    }

    private CartLineItem lineItem(String sku, int quantity) {
        return new CartLineItem("li_" + sku, new Item(sku, sku, 0, null), quantity,
                List.of(new Total("subtotal", null, 0), new Total("total", null, 0)), null);
    }

    private LineItemRequirements requirement(String id, List<LineItem> acceptable, int quantity) {
        return new LineItemRequirements(id, acceptable, quantity);
    }

    private LineItem constraintItem(String id) {
        return new LineItem(id, id);
    }
}