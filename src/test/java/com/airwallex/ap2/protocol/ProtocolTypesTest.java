// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.airwallex.ap2.protocol;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ProtocolTypesTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void amountSerializesAndDeserializes() throws Exception {
        var amount = new Amount(1000, "USD");
        var json = mapper.writeValueAsString(amount);
        var deserialized = mapper.readValue(json, Amount.class);
        assertThat(deserialized).isEqualTo(amount);
    }

    @Test
    void checkoutMandateHasDefaultVct() {
        var mandate = new CheckoutMandate(null, "jwt", "hash", null, null);
        assertThat(mandate.vct()).isEqualTo(CheckoutMandate.VCT);
        assertThat(mandate.vct()).isEqualTo("mandate.checkout.1");
    }

    @Test
    void checkoutMandateSerializesToSnakeCase() throws Exception {
        var mandate = new CheckoutMandate(null, "jwt-value", "hash-value", 1234567890L, null);
        var json = mapper.writeValueAsString(mandate);
        assertThat(json).contains("checkout_jwt");
        assertThat(json).contains("checkout_hash");
    }

    @Test
    void paymentMandateHasDefaultVct() {
        var mandate = PaymentMandate.create("txn", new Merchant("m", "Shop", null),
                new Amount(100, "USD"), new PaymentInstrument("c", "card", null));
        assertThat(mandate.vct()).isEqualTo(PaymentMandate.VCT);
        assertThat(mandate.vct()).isEqualTo("mandate.payment.1");
    }

    @Test
    void paymentMandateSerializesToSnakeCase() throws Exception {
        var mandate = PaymentMandate.create("txn-123", new Merchant("m", "Shop", null),
                new Amount(100, "USD"), new PaymentInstrument("c", "card", null));
        var json = mapper.writeValueAsString(mandate);
        assertThat(json).contains("transaction_id");
        assertThat(json).contains("payment_amount");
        assertThat(json).contains("payment_instrument");
    }

    @Test
    void jsonWebKeyWithKtyOnly() {
        var jwk = new JsonWebKey("EC", null, null, null, null, null, null, null, null, null, null, null);
        assertThat(jwk.kty()).isEqualTo("EC");
        assertThat(jwk.crv()).isNull();
    }

    @Test
    void jsonWebKeyWithAllEcFields() {
        var jwk = new JsonWebKey("EC", "P-256", "x-coord", "y-coord", null, null, "ES256", "key-1",
                null, null, null, null);
        assertThat(jwk.kty()).isEqualTo("EC");
        assertThat(jwk.crv()).isEqualTo("P-256");
        assertThat(jwk.kid()).isEqualTo("key-1");
    }

    @Test
    void merchantWithOptionalWebsite() {
        var m1 = new Merchant("m1", "Shop", null);
        assertThat(m1.website()).isNull();
        var m2 = new Merchant("m2", "Shop", "https://shop.example.com");
        assertThat(m2.website()).isEqualTo("https://shop.example.com");
    }

    @Test
    void paymentInstrumentWithOptionalDescription() {
        var pi = new PaymentInstrument("card-1", "card", "Visa ****1234");
        assertThat(pi.description()).isEqualTo("Visa ****1234");
    }

    @Test
    void pispSerializesToSnakeCase() throws Exception {
        var pisp = new Pisp("Acme Corp", "Acme Pay", "acme.example.com");
        var json = mapper.writeValueAsString(pisp);
        assertThat(json).contains("legal_name");
        assertThat(json).contains("brand_name");
        assertThat(json).contains("domain_name");
    }

    @Test
    void paymentMandateWithPispAndRiskData() {
        var mandate = new PaymentMandate(null, "txn-1", new Merchant("m", "Shop", null), new Amount(500, "EUR"), new PaymentInstrument("c", "card", null), new Pisp("L", "B", "d.com"), "2025-01-01", Map.of("ip", "127.0.0.1"), null, null);
        assertThat(mandate.pisp()).isNotNull();
        assertThat(mandate.riskData()).containsKey("ip");
        assertThat(mandate.executionDate()).isEqualTo("2025-01-01");
    }
}