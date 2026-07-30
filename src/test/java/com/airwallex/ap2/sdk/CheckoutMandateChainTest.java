package com.airwallex.ap2.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.CryptoUtils;
import com.airwallex.ap2.protocol.AllowedMerchants;
import com.airwallex.ap2.protocol.Checkout;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.CheckoutStatus;
import com.airwallex.ap2.protocol.Link;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.OpenCheckoutMandate;
import com.airwallex.ap2.protocol.Total;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CheckoutMandateChainTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Test
    void parseRequiresExactlyTwoPayloads() {
        assertThatThrownBy(() -> CheckoutMandateChain.parse(List.of(Map.of("vct", "mandate.checkout.open.1"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("exactly 2 payloads");
    }

    @Test
    void parseReturnsValidChain() {
        var openPayload = Map.<String, Object>of(
                "vct", "mandate.checkout.open.1",
                "constraints", List.of(),
                "cnf", Map.of());
        var closedPayload = Map.<String, Object>of(
                "vct", "mandate.checkout.1",
                "checkout_jwt", "jwt",
                "checkout_hash", "hash");
        var chain = CheckoutMandateChain.parse(List.of(openPayload, closedPayload));
        assertThat(chain.openMandate().vct()).isEqualTo("mandate.checkout.open.1");
        assertThat(chain.closedMandate().checkoutHash()).isEqualTo("hash");
    }

    @Test
    void verifyFailsWithoutCheckoutJwt() {
        var open = new OpenCheckoutMandate(null, List.of(), Map.of(), null, null);
        var closed = new CheckoutMandate(null, "jwt", "hash", null, null);
        var chain = new CheckoutMandateChain(open, closed);
        var violations = chain.verify("hash", null);
        assertThat(violations).anyMatch(v -> v.contains("checkout_jwt is required"));
    }

    @Test
    void verifyFailsOnCheckoutHashMismatch() throws Exception {
        var checkout = new Checkout("chk-1", null, List.of(), CheckoutStatus.incomplete, "USD",
                List.of(new Total("subtotal", null, 0), new Total("total", null, 0)),
                List.of(), null, null, null, null);
        var checkoutJwt = "hdr." + CryptoUtils.b64urlEncode(
                mapper.writeValueAsString(checkout).getBytes(StandardCharsets.UTF_8)) + ".sig";
        var open = new OpenCheckoutMandate(null, List.of(), Map.of(), null, null);
        var closed = new CheckoutMandate(null, "jwt", "hash", null, null);
        var chain = new CheckoutMandateChain(open, closed);
        var violations = chain.verify("wrong_hash", checkoutJwt);
        assertThat(violations).anyMatch(v -> v.contains("checkout_hash mismatch"));
    }

    @Test
    void verifyPassesWithCorrectHashAndConstraints() throws Exception {
        var checkout = new Checkout("chk-1", new Merchant("m-1", "Shop", null), List.of(), CheckoutStatus.incomplete,
                "USD",
                List.of(new Total("subtotal", null, 0), new Total("total", null, 0)),
                List.of(), null, null, null, null);
        var checkoutJwt = "hdr." + CryptoUtils.b64urlEncode(
                mapper.writeValueAsString(checkout).getBytes(StandardCharsets.UTF_8)) + ".sig";
        var open = new OpenCheckoutMandate(null,
                List.of(new AllowedMerchants(List.of(new Merchant("m-1", "Shop", null)))), Map.of(), null, null);
        var closed = new CheckoutMandate(null, "jwt", "hash", null, null);
        var chain = new CheckoutMandateChain(open, closed);
        var violations = chain.verify("hash", checkoutJwt);
        assertThat(violations).isEmpty();
    }

    @Test
    void extractParsedCheckoutObjectRejectsMalformedJwt() {
        var chain = new CheckoutMandateChain(null, null);
        assertThatThrownBy(() -> chain.extractParsedCheckoutObject("not.a.valid.jwt"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}