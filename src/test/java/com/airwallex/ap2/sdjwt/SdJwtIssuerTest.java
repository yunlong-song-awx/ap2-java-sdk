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

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SdJwtIssuerTest {

    @Test
    void shouldIssueBasicSdJwt() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("sub", "user-123", "name", "Alice");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();

        assertThat(token).endsWith("~");

        var parsed = SdJwtCommon.parseToken(token);
        assertThat(parsed.getIssuerJwt()).isNotBlank();
        assertThat(parsed.getPayload()).containsKey("sub");
        assertThat(parsed.getPayload()).containsKey("name");
        assertThat(parsed.getPayload().get("sub")).isEqualTo("user-123");
        assertThat(parsed.getPayload().get("name")).isEqualTo("Alice");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldSelectivelyDiscloseProperties() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of(
                new SdObject<>("secret"), "hidden-value",
                "public", "visible-value");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();

        assertThat(token).endsWith("~");

        var parsed = SdJwtCommon.parseToken(token);
        List<String> disclosures = parsed.getDisclosures();
        assertThat(disclosures).hasSize(1);

        Map<String, Object> payload = parsed.getPayload();
        assertThat(payload).containsKey("public");
        assertThat(payload.get("public")).isEqualTo("visible-value");
        assertThat(payload).doesNotContainKey("secret");
        assertThat(payload).containsKey("_sd");
        assertThat((List<Object>) payload.get("_sd")).hasSize(1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldSelectivelyDiscloseArrayItems() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("items",
                List.of(new SdObject<>("item-1"), "item-2", new SdObject<>("item-3")));
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();

        assertThat(token).endsWith("~");

        var parsed = SdJwtCommon.parseToken(token);
        List<String> disclosures = parsed.getDisclosures();
        assertThat(disclosures).hasSize(2);

        Map<String, Object> payload = parsed.getPayload();
        List<Object> items = (List<Object>) payload.get("items");
        assertThat(items).hasSize(3);
        assertThat(items.get(1)).isEqualTo("item-2");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldHandleNestedSdObjects() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> inner = Map.of(
                new SdObject<>("inner-secret"), "inner-hidden",
                "inner-public", "inner-visible");
        Map<Object, Object> claims = Map.of("nested", inner, "top", "top-value");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of());
        String token = issuer.getSdJwtIssuance();

        assertThat(token).endsWith("~");

        var parsed = SdJwtCommon.parseToken(token);
        List<String> disclosures = parsed.getDisclosures();
        assertThat(disclosures).hasSize(1);

        Map<String, Object> payload = parsed.getPayload();
        assertThat(payload).containsKey("top");
        assertThat(payload.get("top")).isEqualTo("top-value");

        Map<String, Object> nested = (Map<String, Object>) payload.get("nested");
        assertThat(nested).containsKey("inner-public");
        assertThat(nested.get("inner-public")).isEqualTo("inner-visible");
        assertThat(nested).doesNotContainKey("inner-secret");
        assertThat(nested).containsKey("_sd");
        assertThat((List<Object>) nested.get("_sd")).hasSize(1);
    }

    @Test
    void shouldIncludeIssuerKeyIdInHeader() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("sub", "user-123");
        var issuer = new SdJwtIssuer(claims, privateKey, "my-kid", false, Map.of());
        String token = issuer.getSdJwtIssuance();

        var parsed = SdJwtCommon.parseToken(token);
        JWSObject jws = JWSObject.parse(parsed.getIssuerJwt());
        assertThat(jws.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(jws.getHeader().getKeyID()).isEqualTo("my-kid");
    }

    @Test
    void shouldIncludeExtraHeaderParameters() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("sub", "user-123");
        var issuer = new SdJwtIssuer(claims, privateKey, null, false, Map.of("typ", "kb+sd-jwt"));
        String token = issuer.getSdJwtIssuance();

        var parsed = SdJwtCommon.parseToken(token);
        JWSObject jws = JWSObject.parse(parsed.getIssuerJwt());
        assertThat(jws.getHeader().getType().getType()).isEqualTo("kb+sd-jwt");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldAddDecoyClaims() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        ECPrivateKey privateKey = ecKey.toECPrivateKey();

        Map<Object, Object> claims = Map.of("sub", "user-123");
        var issuer = new SdJwtIssuer(claims, privateKey, null, true, Map.of());
        String token = issuer.getSdJwtIssuance();

        assertThat(token).endsWith("~");

        var parsed = SdJwtCommon.parseToken(token);
        Map<String, Object> payload = parsed.getPayload();

        List<Object> sdDigests = (List<Object>) payload.get("_sd");
        assertThat(sdDigests).isNotNull();
        assertThat(sdDigests.size()).isBetween(1, 3);

        assertThat(parsed.getDisclosures()).isEmpty();
    }

    @Test
    void shouldRejectMalformedToken() {
        assertThatThrownBy(() -> SdJwtCommon.parseToken("not-a-valid-sd-jwt"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> SdJwtCommon.parseToken("~"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}