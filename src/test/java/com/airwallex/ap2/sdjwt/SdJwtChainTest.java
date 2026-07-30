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

package com.airwallex.ap2.sdjwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.CryptoUtils;
import com.airwallex.ap2.SdJwt;
import com.airwallex.ap2.mandate.MandateClient;
import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.sdjwt.SdJwtChain.PublicKeyProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SdJwtChainTest {
    private final ECKey issuerKey;
    private final ECKey holderKey;

    {
        try {
            issuerKey = new ECKeyGenerator(Curve.P_256).generate();
            holderKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private final MandateClient client = new MandateClient();
    private final long now = System.currentTimeMillis() / 1000;

    private CheckoutMandate checkoutMandate() {
        return new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.dGVzdA.sig",
                CryptoUtils.computeSha256B64url("test"), now, null);
    }

    private PaymentMandate paymentMandate() {
        return new PaymentMandate(null, "txn-1", new Merchant("m1", "Shop", null), new Amount(500L, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, now, null);
    }

    @Test
    void verifyChainThrowsOnEmptyTokenList() {
        assertThatThrownBy(() -> SdJwtChain.verifyChain(List.of(),
                (PublicKeyProvider) token -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 300, null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void verifyChainSucceedsWithSingleRootToken() throws Exception {
        String token = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(),
                null, null, null, null);
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(token);
        List<Map<String, Object>> payloads = SdJwtChain.verifyChain(List.of(parsed),
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 300, null, null, now);
        assertThat(payloads).isNotEmpty();
    }

    @Test
    void verifyChainRejectsExpiredToken() throws Exception {
        CheckoutMandate expiredMandate = new CheckoutMandate(null, "jwt", "hash", now - 1000, now - 500);
        String token = SdJwt.create(expiredMandate, issuerKey.toECPrivateKey(), null, null, false,
                Map.of("exp", now - 500)).getSdJwtIssuance();
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(token);
        assertThatThrownBy(() -> SdJwtChain.verifyChain(List.of(parsed),
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 0, null, null, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void verifyChainRejectsFutureIat() throws Exception {
        String token = SdJwt.create(checkoutMandate(), issuerKey.toECPrivateKey(), null, null, false,
                Map.of("iat", now + 1000)).getSdJwtIssuance();
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(token);
        assertThatThrownBy(() -> SdJwtChain.verifyChain(List.of(parsed),
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 0, null, null, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("future");
    }

    @Test
    void verifyChainValidatesTwoHopChain() throws Exception {
        String rootToken = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(),
                null, null, holderKey.toECPublicKey(), null);
        String chainToken = client.present(holderKey.toECPrivateKey(), rootToken,
                List.of(paymentMandate()), null, null, null, "nonce-1",
                "https://verifier.example.com", "sd_hash");
        List<Map<String, Object>> payloads = client.verify(chainToken,
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                },
                "https://verifier.example.com", "nonce-1", 300, now);
        assertThat(payloads).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void verifyChainWithNbfClaimInThePastPasses() throws Exception {
        String token = SdJwt.create(checkoutMandate(), issuerKey.toECPrivateKey(), null, null, false,
                Map.of("nbf", now - 100)).getSdJwtIssuance();
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(token);
        List<Map<String, Object>> payloads = SdJwtChain.verifyChain(List.of(parsed),
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 300, null, null, now);
        assertThat(payloads).isNotEmpty();
    }

    @Test
    void verifyChainWithNbfInFarFutureFails() throws Exception {
        String token = SdJwt.create(checkoutMandate(), issuerKey.toECPrivateKey(), null, null, false,
                Map.of("nbf", now + 1000)).getSdJwtIssuance();
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(token);
        assertThatThrownBy(() -> SdJwtChain.verifyChain(List.of(parsed),
                (PublicKeyProvider) t -> {
                    try {
                        return issuerKey.toECPublicKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, 0, null, null, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not valid before");
    }
}