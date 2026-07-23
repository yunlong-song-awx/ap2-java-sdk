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

package com.airwallex.ap2;

import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.sdjwt.DisclosureMetadata;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.airwallex.ap2.sdjwt.SdJwtCommon.ParsedToken;
import com.airwallex.ap2.sdjwt.SdJwtHolder;
import com.airwallex.ap2.sdjwt.SdJwtIssuer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SdJwtRoundTripTest {
    private final ECKey issuerKey;

    {
        try {
            issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void createAndVerifyBasicSdJwt() throws Exception {
        var payload = new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.test.sig",
                CryptoUtils.computeSha256B64url("test"), null, null);
        SdJwtIssuer issuer = SdJwt.create(payload, issuerKey.toECPrivateKey(), "key-1", null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        assertThat(token).contains("~");
        assertThat(token).endsWith("~");

        Map<String, Object> verified = SdJwt.verify(token, issuerKey.toECPublicKey());
        assertThat(verified).containsKey("_sd_alg");
        assertThat(verified.get("_sd_alg")).isEqualTo("sha-256");
        assertThat(verified).containsKey("delegate_payload");
    }

    @Test
    void createSdJwtWithSelectiveDisclosure() throws Exception {
        var payload = new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.test.sig",
                CryptoUtils.computeSha256B64url("test"), null, null);
        DisclosureMetadata sd = DisclosureMetadata.ofSdKeys(List.of("checkout_jwt", "checkout_hash"));
        SdJwtIssuer issuer = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, sd, false, Map.of());
        String token = issuer.getSdJwtIssuance();

        ParsedToken parsed = SdJwtCommon.parseToken(token);
        assertThat(parsed.getDisclosures()).isNotEmpty();

        Map<String, Object> verified = SdJwt.verify(token, issuerKey.toECPublicKey());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dp = (List<Map<String, Object>>) verified.get("delegate_payload");
        assertThat(dp).hasSize(1);
        assertThat(dp.get(0)).containsKey("checkout_jwt");
        assertThat(dp.get(0)).containsKey("checkout_hash");
    }

    @Test
    void createSdJwtWithDecoyClaims() throws Exception {
        var payload = new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.test.sig",
                CryptoUtils.computeSha256B64url("test"), null, null);
        SdJwtIssuer issuer = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, null, true, Map.of());
        String token = issuer.getSdJwtIssuance();

        Map<String, Object> verified = SdJwt.verify(token, issuerKey.toECPublicKey());
        assertThat(verified).containsKey("delegate_payload");
    }

    @Test
    void verifyFailsWithWrongKey() throws Exception {
        var otherKey = new ECKeyGenerator(Curve.P_256).generate();
        var payload = new CheckoutMandate(null, "jwt", "hash", null, null);
        String token = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, null, false, Map.of()).getSdJwtIssuance();
        assertThatThrownBy(() -> SdJwt.verify(token, otherKey.toECPublicKey()))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SD-JWT verification failed");
    }

    @Test
    void verifyChecksAudienceWhenExpected() throws Exception {
        var payload = new CheckoutMandate(null, "jwt", "hash", null, null);
        String token = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, null, false, Map.of()).getSdJwtIssuance();
        assertThatThrownBy(() -> SdJwt.verify(token, issuerKey.toECPublicKey(), "https://example.com", null))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("SD-JWT verification failed");
    }

    @Test
    void verifyChecksNonceWhenExpected() throws Exception {
        var payload = new CheckoutMandate(null, "jwt", "hash", null, null);
        String token = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, null, false, Map.of()).getSdJwtIssuance();
        assertThatThrownBy(() -> SdJwt.verify(token, issuerKey.toECPublicKey(), null, "nonce-123"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("SD-JWT verification failed");
    }

    @Test
    void holderCanSelectivelyDiscloseClaims() throws Exception {
        var payload = new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.test.sig",
                CryptoUtils.computeSha256B64url("test"), null, null);
        DisclosureMetadata sd = DisclosureMetadata.ofSdKeys(List.of("checkout_jwt", "checkout_hash"));
        String token = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, sd, false, Map.of()).getSdJwtIssuance();

        SdJwtHolder holder = new SdJwtHolder(token);
        assertThat(holder.getInputDisclosures()).hasSizeGreaterThanOrEqualTo(2);

        holder.createPresentation(Map.of("checkout_jwt", true));
        String presentation = holder.getSdJwtPresentation();
        assertThat(presentation).isNotBlank();

        Map<String, Object> verified = SdJwt.verify(presentation, issuerKey.toECPublicKey());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dp = (List<Map<String, Object>>) verified.get("delegate_payload");
        assertThat(dp.get(0)).containsKey("checkout_jwt");
        assertThat(dp.get(0)).doesNotContainKey("checkout_hash");
    }

    @Test
    void holderCreatesPresentationWithNoDisclosures() throws Exception {
        var payload = new CheckoutMandate(null, "jwt", "hash", null, null);
        DisclosureMetadata sd = DisclosureMetadata.ofSdKeys(List.of("checkout_jwt"));
        String token = SdJwt.create(payload, issuerKey.toECPrivateKey(), null, sd, false, Map.of()).getSdJwtIssuance();

        SdJwtHolder holder = new SdJwtHolder(token);
        holder.createPresentation(Map.of("nonexistent", true));
        assertThat(holder.getSdJwtPresentation()).endsWith("~");
    }

    @Test
    void paymentMandateRoundTrip() throws Exception {
        var mandate = PaymentMandate.create("txn-123",
                new Merchant("merchant-1", "Test Shop", null),
                new Amount(1000, "USD"),
                new PaymentInstrument("card-1", "card", null));
        String token = SdJwt.create(mandate, issuerKey.toECPrivateKey(), null, null, false, Map.of()).getSdJwtIssuance();
        Map<String, Object> verified = SdJwt.verify(token, issuerKey.toECPublicKey());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dp = (List<Map<String, Object>>) verified.get("delegate_payload");
        assertThat(dp.get(0).get("transaction_id")).isEqualTo("txn-123");
        assertThat(dp.get(0).get("vct")).isEqualTo("mandate.payment.1");
    }
}