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
import com.airwallex.ap2.protocol.JsonWebKey;
import com.airwallex.ap2.sdjwt.SdJwtCommon.ParsedToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SdJwtCommonTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    record TestPayload(String myField, String optionalField) {
        TestPayload(String myField) {
            this(myField, null);
        }
    }

    private static String createDummyJwt() {
        String header = CryptoUtils.b64urlEncode(
                "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}".getBytes(StandardCharsets.UTF_8));
        String payload = CryptoUtils.b64urlEncode(
                "{\"_sd_alg\":\"sha-256\",\"iat\":1234567890,\"aud\":\"test-aud\",\"nonce\":\"test-nonce\"}"
                        .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".dummy-sig";
    }

    private static String createDummySdJwtToken() {
        return createDummyJwt() + "~";
    }

    private static String createDummySdJwtTokenWithDisclosures() {
        String disclosure = CryptoUtils.b64urlEncode(
                "[\"abc\",\"def\"]".getBytes(StandardCharsets.UTF_8));
        return createDummyJwt() + "~" + disclosure + "~";
    }

    private static String createDummyKbJwt() {
        String header = CryptoUtils.b64urlEncode(
                "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}".getBytes(StandardCharsets.UTF_8));
        String payload = CryptoUtils.b64urlEncode(
                "{\"iat\":1234567890,\"aud\":\"test-aud\",\"nonce\":\"test-nonce\"}"
                        .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".dummy-sig";
    }

    private static String createDummySdJwtTokenWithKbJwt() {
        return createDummyJwt() + "~" + createDummyKbJwt();
    }

    @Nested
    class ParseTokenTest {
        @Test
        void parseTokenWithDisclosures() {
            String token = createDummySdJwtTokenWithDisclosures();
            ParsedToken parsed = SdJwtCommon.parseToken(token);
            assertThat(parsed.getIssuerJwt()).isEqualTo(createDummyJwt());
            assertThat(parsed.getDisclosures()).hasSize(1);
            assertThat(parsed.getKbJwt()).isNull();
        }

        @Test
        void parseTokenWithoutDisclosures() {
            String token = createDummySdJwtToken();
            ParsedToken parsed = SdJwtCommon.parseToken(token);
            assertThat(parsed.getIssuerJwt()).isEqualTo(createDummyJwt());
            assertThat(parsed.getDisclosures()).isEmpty();
            assertThat(parsed.getKbJwt()).isNull();
        }

        @Test
        void parseTokenWithKbJwt() {
            String token = createDummySdJwtTokenWithKbJwt();
            ParsedToken parsed = SdJwtCommon.parseToken(token);
            assertThat(parsed.getIssuerJwt()).isEqualTo(createDummyJwt());
            assertThat(parsed.getDisclosures()).isEmpty();
            assertThat(parsed.getKbJwt()).isEqualTo(createDummyKbJwt());
        }

        @Test
        void parseTokenEmptyIssuerJwt() {
            assertThatThrownBy(() -> SdJwtCommon.parseToken("~dummy"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("empty issuer JWT");
        }

        @Test
        void parseTokenMissingDisclosureSeparator() {
            assertThatThrownBy(() -> SdJwtCommon.parseToken("no-tilde"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("missing disclosure separator");
        }
    }

    @Nested
    class HashingTest {
        @Test
        void computeSdHashProducesNonBlankHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            String hash = SdJwtCommon.computeSdHash(parsed);
            assertThat(hash).isNotBlank();
        }

        @Test
        void computeIssuerJwtHashProducesNonBlankHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            String hash = SdJwtCommon.computeIssuerJwtHash(parsed);
            assertThat(hash).isNotBlank();
        }

        @Test
        void computeDisclosureDigestProducesNonBlankHash() {
            String disclosure = CryptoUtils.b64urlEncode(
                    "[\"abc\",\"def\"]".getBytes(StandardCharsets.UTF_8));
            String digest = SdJwtCommon.computeDisclosureDigest(disclosure, "sha-256");
            assertThat(digest).isNotBlank();
        }

        @Test
        void differentTokensProduceDifferentSdHash() {
            ParsedToken parsed1 = SdJwtCommon.parseToken(createDummySdJwtToken());
            String otherHeader = CryptoUtils.b64urlEncode(
                    "{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
            String otherPayload = CryptoUtils.b64urlEncode(
                    "{\"_sd_alg\":\"sha-256\",\"iat\":987654321}".getBytes(StandardCharsets.UTF_8));
            String otherJwt = otherHeader + "." + otherPayload + ".dummy-sig";
            ParsedToken parsed2 = SdJwtCommon.parseToken(otherJwt + "~");
            assertThat(SdJwtCommon.computeSdHash(parsed1))
                    .isNotEqualTo(SdJwtCommon.computeSdHash(parsed2));
        }

        @Test
        void differentTokensProduceDifferentIssuerJwtHash() {
            ParsedToken parsed1 = SdJwtCommon.parseToken(createDummySdJwtToken());
            String otherHeader = CryptoUtils.b64urlEncode(
                    "{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
            String otherPayload = CryptoUtils.b64urlEncode(
                    "{\"_sd_alg\":\"sha-256\",\"iat\":987654321}".getBytes(StandardCharsets.UTF_8));
            String otherJwt = otherHeader + "." + otherPayload + ".dummy-sig";
            ParsedToken parsed2 = SdJwtCommon.parseToken(otherJwt + "~");
            assertThat(SdJwtCommon.computeIssuerJwtHash(parsed1))
                    .isNotEqualTo(SdJwtCommon.computeIssuerJwtHash(parsed2));
        }

        @Test
        void differentDisclosuresProduceDifferentDigests() {
            String disc1 = CryptoUtils.b64urlEncode(
                    "[\"a\",\"b\"]".getBytes(StandardCharsets.UTF_8));
            String disc2 = CryptoUtils.b64urlEncode(
                    "[\"c\",\"d\"]".getBytes(StandardCharsets.UTF_8));
            assertThat(SdJwtCommon.computeDisclosureDigest(disc1, "sha-256"))
                    .isNotEqualTo(SdJwtCommon.computeDisclosureDigest(disc2, "sha-256"));
        }
    }

    @Nested
    class BindingTest {
        @Test
        void computeBindingSdHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map.Entry<String, String> binding = SdJwtCommon.computeBinding(parsed,
                    SdJwtCommon.HASH_MODE_SD);
            String claim = binding.getKey();
            String value = binding.getValue();
            assertThat(claim).isEqualTo("sd_hash");
            assertThat(value).isNotBlank();
        }

        @Test
        void computeBindingIssuerJwtHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map.Entry<String, String> binding = SdJwtCommon.computeBinding(parsed,
                    SdJwtCommon.HASH_MODE_ISSUER_JWT);
            String claim = binding.getKey();
            String value = binding.getValue();
            assertThat(claim).isEqualTo("issuer_jwt_hash");
            assertThat(value).isNotBlank();
        }

        @Test
        void computeBindingInvalidHashMode() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThatThrownBy(() -> SdJwtCommon.computeBinding(parsed, "invalid_mode"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void verifyBindingValidSdHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map<String, Object> payload = new HashMap<>();
            payload.put("sd_hash", SdJwtCommon.computeSdHash(parsed));
            SdJwtCommon.verifyBinding(payload, parsed);
        }

        @Test
        void verifyBindingValidIssuerJwtHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map<String, Object> payload = new HashMap<>();
            payload.put("issuer_jwt_hash", SdJwtCommon.computeIssuerJwtHash(parsed));
            SdJwtCommon.verifyBinding(payload, parsed);
        }

        @Test
        void verifyBindingMismatchedHash() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map<String, Object> payload = new HashMap<>();
            payload.put("sd_hash", "wrong-hash");
            assertThatThrownBy(() -> SdJwtCommon.verifyBinding(payload, parsed))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class ClaimHelpersTest {
        @Test
        void delegateClaimsFromObjectFiltersNullValues() {
            TestPayload obj = new TestPayload("value");
            Map<String, Object> result = SdJwtCommon.delegateClaimsFromObject(obj);
            assertThat(result).containsKey("my_field");
            assertThat(result).doesNotContainKey("optional_field");
            assertThat(result.get("my_field")).isEqualTo("value");
        }

        @Test
        void headerParametersWithBoth() {
            Map<String, Object> params = SdJwtCommon.headerParameters("kid-1", "typ-1");
            assertThat(params).containsEntry("kid", "kid-1");
            assertThat(params).containsEntry("typ", "typ-1");
        }

        @Test
        void headerParametersWithNullKid() {
            Map<String, Object> params = SdJwtCommon.headerParameters(null, "typ-1");
            assertThat(params).doesNotContainKey("kid");
            assertThat(params).containsEntry("typ", "typ-1");
        }

        @Test
        void headerParametersWithNullTyp() {
            Map<String, Object> params = SdJwtCommon.headerParameters("kid-1", null);
            assertThat(params).containsEntry("kid", "kid-1");
            assertThat(params).doesNotContainKey("typ");
        }

        @Test
        void verifyExpectedClaimsValid() {
            Map<String, Object> payload = new HashMap<>();
            payload.put("iat", 1234567890);
            payload.put("aud", "test-aud");
            payload.put("nonce", "test-nonce");
            SdJwtCommon.verifyExpectedClaims(payload, "test-aud", "test-nonce", "test");
        }

        @Test
        void verifyExpectedClaimsMissingIat() {
            Map<String, Object> payload = new HashMap<>();
            payload.put("aud", "test-aud");
            payload.put("nonce", "test-nonce");
            assertThatThrownBy(() ->
                    SdJwtCommon.verifyExpectedClaims(payload, "test-aud", "test-nonce", "test"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("missing required 'iat' claim");
        }

        @Test
        void verifyExpectedClaimsAudMismatch() {
            Map<String, Object> payload = new HashMap<>();
            payload.put("iat", 1234567890);
            payload.put("aud", "wrong-aud");
            payload.put("nonce", "test-nonce");
            assertThatThrownBy(() ->
                    SdJwtCommon.verifyExpectedClaims(payload, "test-aud", "test-nonce", "test"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("aud mismatch");
        }
    }

    @Nested
    class SelectivelyDisclosableClaimsTest {
        @Test
        void selectivelyDisclosableClaimsDefault() {
            Map<String, Object> delegateClaims = Map.of("key", "value");
            Map<Object, Object> result = SdJwtCommon.selectivelyDisclosableClaims(
                    delegateClaims, new DisclosureMetadata(), Map.of());
            assertThat(result).containsKey("delegate_payload");
            @SuppressWarnings("unchecked")
            List<Object> delegatePayload = (List<Object>) result.get("delegate_payload");
            assertThat(delegatePayload).hasSize(1);
        }

        @Test
        void selectivelyDisclosableClaimsWithExtraClaims() {
            Map<String, Object> delegateClaims = Map.of("key", "value");
            Map<String, Object> extraClaims = Map.of("extra", "data");
            Map<Object, Object> result = SdJwtCommon.selectivelyDisclosableClaims(
                    delegateClaims, new DisclosureMetadata(), extraClaims);
            assertThat(result).containsKey("extra");
            assertThat(result.get("extra")).isEqualTo("data");
        }

        @Test
        @SuppressWarnings("unchecked")
        void selectivelyDisclosableClaimsWithSdKeys() {
            Map<String, Object> delegateClaims = new HashMap<>();
            delegateClaims.put("secret", "value");
            delegateClaims.put("public", "visible");
            DisclosureMetadata meta = DisclosureMetadata.ofSdKeys(List.of("secret"));
            Map<Object, Object> result = SdJwtCommon.selectivelyDisclosableClaims(
                    delegateClaims, meta, Map.of());
            List<Object> delegatePayload = (List<Object>) result.get("delegate_payload");
            SdObject<?> sdObj = (SdObject<?>) delegatePayload.get(0);
            Map<Object, Object> inner = (Map<Object, Object>) sdObj.wrapped();
            assertThat(inner.get(new SdObject<>("secret"))).isEqualTo("value");
            assertThat(inner.get("public")).isEqualTo("visible");
        }
    }

    @Nested
    class ParsedTokenCnfJwkTest {
        @Test
        void cnfJwkThrowsWhenNotVerified() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThatThrownBy(() -> parsed.cnfJwk())
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void cnfJwkReturnsNullWhenNoCnf() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map<String, Object> verifiedPayload = Map.of();
            ParsedToken verified = parsed.withVerifiedPayload(verifiedPayload, null);
            assertThat(verified.cnfJwk()).isNull();
        }

        @Test
        void cnfJwkReturnsNullWhenCnfHasNoJwk() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            Map<String, Object> verifiedPayload = new HashMap<>();
            verifiedPayload.put("cnf", Map.of());
            ParsedToken verified = parsed.withVerifiedPayload(verifiedPayload, null);
            assertThat(verified.cnfJwk()).isNull();
        }

        @Test
        void cnfJwkReturnsPublicKeyWhenCnfJwkIsPresent() throws Exception {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
            JsonWebKey jwk = CryptoUtils.ecKeyToJwk(ecKey.toECPublicKey());
            Map<String, Object> jwkMap = new HashMap<>();
            jwkMap.put("kty", jwk.kty());
            jwkMap.put("crv", jwk.crv());
            jwkMap.put("x", jwk.x());
            jwkMap.put("y", jwk.y());
            Map<String, Object> cnf = new HashMap<>();
            cnf.put("jwk", jwkMap);
            Map<String, Object> verifiedPayload = new HashMap<>();
            verifiedPayload.put("cnf", cnf);
            ParsedToken verified = parsed.withVerifiedPayload(verifiedPayload, null);
            ECPublicKey result = verified.cnfJwk();
            assertThat(result).isNotNull();
        }
    }

    @Nested
    class KeyHelpersTest {
        @Test
        void ecKeyFromJwkValidKey() throws Exception {
            ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();
            JsonWebKey jwk = CryptoUtils.ecKeyToJwk(ecKey.toECPublicKey());
            ECPublicKey result = SdJwtCommon.ecKeyFromJwk(jwk);
            assertThat(result).isNotNull();
        }

        @Test
        void ecKeyFromJwkMissingX() {
            JsonWebKey jwk = new JsonWebKey("EC", "P-256", null, "y", null, null, null, null, null, null, null, null);
            assertThatThrownBy(() -> SdJwtCommon.ecKeyFromJwk(jwk))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("missing x coordinate");
        }

        @Test
        void ecKeyFromJwkMissingY() {
            JsonWebKey jwk = new JsonWebKey("EC", "P-256", "x", null, null, null, null, null, null, null, null, null);
            assertThatThrownBy(() -> SdJwtCommon.ecKeyFromJwk(jwk))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("missing y coordinate");
        }

        @Test
        void ecKeyFromJwkInvalidCoordinates() {
            JsonWebKey jwk = new JsonWebKey("EC", "P-256", "not-valid-x", "not-valid-y", null, null, null, null, null, null, null, null);
            assertThatThrownBy(() -> SdJwtCommon.ecKeyFromJwk(jwk))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    class ParsedTokenTest {
        @Test
        void getTyp() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThat(parsed.getTyp()).isEqualTo("kb+jwt");
        }

        @Test
        void getSdAlg() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThat(parsed.getSdAlg()).isEqualTo("sha-256");
        }

        @Test
        void getSdJwtWithDisclosures() {
            String token = createDummySdJwtTokenWithDisclosures();
            ParsedToken parsed = SdJwtCommon.parseToken(token);
            String sdJwt = parsed.getSdJwt();
            assertThat(sdJwt).startsWith(createDummyJwt());
            assertThat(sdJwt).endsWith("~");
            assertThat(sdJwt).contains("~");
        }

        @Test
        void getSdJwtWithoutDisclosures() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThat(parsed.getSdJwt()).isEqualTo(createDummyJwt() + "~");
        }

        @Test
        void getCanonicalWithKbJwt() {
            String token = createDummySdJwtTokenWithKbJwt();
            ParsedToken parsed = SdJwtCommon.parseToken(token);
            String canonical = parsed.getCanonical();
            assertThat(canonical).startsWith(createDummyJwt());
            assertThat(canonical).endsWith(createDummyKbJwt());
        }

        @Test
        void getCanonicalWithoutKbJwt() {
            ParsedToken parsed = SdJwtCommon.parseToken(createDummySdJwtToken());
            assertThat(parsed.getCanonical()).isEqualTo(createDummyJwt() + "~");
        }
    }
}