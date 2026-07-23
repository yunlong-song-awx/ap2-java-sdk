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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.mandate.MandateClient;
import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.airwallex.ap2.sdjwt.SdJwtCommon.ParsedToken;
import com.airwallex.ap2.sdjwt.SdJwtIssuer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

record PayloadWithCnf(String vct, Map<String, Object> cnf) {
    PayloadWithCnf(Map<String, Object> cnf) {
        this("test", cnf);
    }
}

class KbSdJwtTest {
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

    private String createRootToken(boolean embedHolder) {
        CheckoutMandate payload = new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.dGVzdA.sig",
                CryptoUtils.computeSha256B64url("test"), System.currentTimeMillis() / 1000, null);
        try {
            if (embedHolder) {
                MandateClient mandate = new MandateClient();
                return mandate.create(List.of(payload), issuerKey.toECPrivateKey(), null, null,
                        holderKey.toECPublicKey(), null);
            } else {
                return SdJwt.create(payload, issuerKey.toECPrivateKey(), null, null, false, Map.of())
                        .getSdJwtIssuance();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String createRootToken() {
        return createRootToken(true);
    }

    @Test
    void createProducesTerminalKbSdJwtWhenPayloadHasNoCnf() throws Exception {
        String rootToken = createRootToken();
        ParsedToken rootParsed = SdJwtCommon.parseToken(rootToken);
        Map<String, Object> rootVerified = SdJwt.verify(rootToken, issuerKey.toECPublicKey());
        ParsedToken rootWithVerified = rootParsed.withVerifiedPayload(rootVerified, List.of(rootVerified));
        PaymentMandate paymentPayload = new PaymentMandate(null, "txn-1",
                new Merchant("m1", "Shop", null),
                new Amount(500, "USD"),
                new PaymentInstrument("card-1", "card", null),
                null, null, null, System.currentTimeMillis() / 1000, null, null);
        SdJwtIssuer kbIssuer = KbSdJwt.create(rootWithVerified, holderKey.toECPrivateKey(),
                paymentPayload, "https://verifier.example.com", "nonce-123", null, null, "sd_hash", false);
        String kbToken = kbIssuer.getSdJwtIssuance();
        assertThat(kbToken).endsWith("~");
        ParsedToken parsed = SdJwtCommon.parseToken(kbToken);
        assertThat(parsed.getTyp()).isIn(KbSdJwt.TYP_TERMINAL);
    }

    @Test
    void createThrowsWhenAudIsBlank() throws Exception {
        String rootToken = createRootToken();
        ParsedToken rootParsed = SdJwtCommon.parseToken(rootToken);
        Map<String, Object> rootVerified = SdJwt.verify(rootToken, issuerKey.toECPublicKey());
        ParsedToken rootWithVerified = rootParsed.withVerifiedPayload(rootVerified, List.of(rootVerified));
        PaymentMandate paymentPayload = new PaymentMandate(null, "txn-1",
                new Merchant("m1", "Shop", null),
                new Amount(500, "USD"),
                new PaymentInstrument("card-1", "card", null),
                null, null, null, System.currentTimeMillis() / 1000, null, null);
        assertThatThrownBy(() -> {
            KbSdJwt.create(rootWithVerified, holderKey.toECPrivateKey(), paymentPayload, "", "nonce-123",
                    null, null, "sd_hash", false);
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void createThrowsWhenNonceIsBlank() throws Exception {
        String rootToken = createRootToken();
        ParsedToken rootParsed = SdJwtCommon.parseToken(rootToken);
        Map<String, Object> rootVerified = SdJwt.verify(rootToken, issuerKey.toECPublicKey());
        ParsedToken rootWithVerified = rootParsed.withVerifiedPayload(rootVerified, List.of(rootVerified));
        PaymentMandate paymentPayload = new PaymentMandate(null, "txn-1",
                new Merchant("m1", "Shop", null),
                new Amount(500, "USD"),
                new PaymentInstrument("card-1", "card", null),
                null, null, null, System.currentTimeMillis() / 1000, null, null);
        assertThatThrownBy(() -> {
            KbSdJwt.create(rootWithVerified, holderKey.toECPrivateKey(), paymentPayload, "https://example.com", "",
                    null, null, "sd_hash", false);
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void createProducesIntermediateKbSdJwtWhenPayloadHasCnf() throws Exception {
        String rootToken = createRootToken();
        ParsedToken rootParsed = SdJwtCommon.parseToken(rootToken);
        Map<String, Object> rootVerified = SdJwt.verify(rootToken, issuerKey.toECPublicKey());
        ParsedToken rootWithVerified = rootParsed.withVerifiedPayload(rootVerified, List.of(rootVerified));
        ECKey nextHolderKey = new ECKeyGenerator(Curve.P_256).generate();
        Map<String, Object> cnfMap = Map.of("jwk", Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", nextHolderKey.getX().toString(),
                "y", nextHolderKey.getY().toString()));
        PayloadWithCnf payload = new PayloadWithCnf(cnfMap);
        SdJwtIssuer kbIssuer = KbSdJwt.create(rootWithVerified, holderKey.toECPrivateKey(),
                payload, "https://verifier.example.com", "nonce-123", null, null, "sd_hash", false);
        String kbToken = kbIssuer.getSdJwtIssuance();
        assertThat(kbToken).endsWith("~");
        ParsedToken parsed = SdJwtCommon.parseToken(kbToken);
        assertThat(parsed.getTyp()).isIn(KbSdJwt.TYP_INTERMEDIATE);
    }

    @Test
    void createWithIssuerJwtHashBindingMode() throws Exception {
        String rootToken = createRootToken();
        ParsedToken rootParsed = SdJwtCommon.parseToken(rootToken);
        Map<String, Object> rootVerified = SdJwt.verify(rootToken, issuerKey.toECPublicKey());
        ParsedToken rootWithVerified = rootParsed.withVerifiedPayload(rootVerified, List.of(rootVerified));
        PaymentMandate paymentPayload = new PaymentMandate(null, "txn-1",
                new Merchant("m1", "Shop", null),
                new Amount(500, "USD"),
                new PaymentInstrument("card-1", "card", null),
                null, null, null, System.currentTimeMillis() / 1000, null, null);
        SdJwtIssuer kbIssuer = KbSdJwt.create(rootWithVerified, holderKey.toECPrivateKey(),
                paymentPayload, "https://verifier.example.com", "nonce-123", null, null, "issuer_jwt_hash", false);
        String kbToken = kbIssuer.getSdJwtIssuance();
        assertThat(kbToken).endsWith("~");
        ParsedToken parsed = SdJwtCommon.parseToken(kbToken);
        assertThat(parsed.getTyp()).isIn(KbSdJwt.TYP_TERMINAL);
        assertThat(parsed.getPayload()).containsKey("issuer_jwt_hash");
    }
}