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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SdJwtHolderTest {

    @Test
    void inputDisclosuresReturnsAllDisclosuresFromIssuance() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of(
                new SdObject<>("a"), "1",
                new SdObject<>("b"), "2",
                "c", "3");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        var holder = new SdJwtHolder(token);
        assertThat(holder.getInputDisclosures()).hasSize(2);
    }

    @Test
    void createPresentationIncludesOnlyMatchingPropertyDisclosures() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();
        ECPublicKey publicKey = ecKey.toECPublicKey();

        Map<Object, Object> claims = Map.of(
                new SdObject<>("name"), "Alice",
                new SdObject<>("email"), "alice@example.com",
                "sub", "user-1");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        var holder = new SdJwtHolder(token);
        holder.createPresentation(Map.of("name", true));
        String presentation = holder.getSdJwtPresentation();
        assertThat(presentation).endsWith("~");
        var verifier = new SdJwtVerifier(presentation, (issuerStr, header) -> publicKey, null, null);
        Map<String, Object> payload = verifier.getVerifiedPayload();
        assertThat(payload.get("name")).isEqualTo("Alice");
        assertThat(payload).doesNotContainKey("email");
    }

    @Test
    void createPresentationWithEmptyClaimsRevealsNothing() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of(new SdObject<>("secret"), "hidden");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        var holder = new SdJwtHolder(token);
        holder.createPresentation(Map.of());
        String presentation = holder.getSdJwtPresentation();
        assertThat(presentation).endsWith("~");
        var parsed = SdJwtCommon.parseToken(presentation);
        assertThat(parsed.getDisclosures()).isEmpty();
    }

    @Test
    void createPresentationIncludesArrayElementsWithVctKey() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("items",
                List.of(
                        new SdObject<>(Map.of("vct", "mandate.checkout.1", "data", "test")),
                        new SdObject<>(Map.of("other", "value"))));
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        var holder = new SdJwtHolder(token);
        holder.createPresentation(Map.of("anything", true));
        var parsed = SdJwtCommon.parseToken(holder.getSdJwtPresentation());
        assertThat(parsed.getDisclosures().size()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void createPresentationIncludesScalarArrayElementsWhenClaimsToDiscloseHasTrueValues() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("tags",
                List.of(new SdObject<>("tag1"), new SdObject<>("tag2")));
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();
        var holder = new SdJwtHolder(token);
        holder.createPresentation(Map.of("reveal", true));
        var parsed = SdJwtCommon.parseToken(holder.getSdJwtPresentation());
        assertThat(parsed.getDisclosures()).hasSize(2);
    }
}