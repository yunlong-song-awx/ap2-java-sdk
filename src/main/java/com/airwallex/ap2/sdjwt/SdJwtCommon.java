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

import com.airwallex.ap2.CryptoUtils;
import com.airwallex.ap2.protocol.JsonWebKey;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SdJwtCommon {
    private SdJwtCommon() {
    }

    public static final String HASH_MODE_SD = "sd_hash";
    public static final String HASH_MODE_ISSUER_JWT = "issuer_jwt_hash";

    private static final int COMPACT_JWT_PARTS = 3;
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    private static final Map<String, String> HASH_ALGORITHMS = Map.of(
            "sha-256", "SHA-256",
            "sha-384", "SHA-384",
            "sha-512", "SHA-512");

    // ── ParsedToken ────────────────────────────────────────────────────────

    public static final class ParsedToken {
        private final String issuerJwt;
        private final List<String> disclosures;
        private final String kbJwt;
        private final Map<String, Object> header;
        private final Map<String, Object> payload;
        private final Map<String, Object> verifiedPayload;
        private final List<Map<String, Object>> delegateItems;

        public ParsedToken(String issuerJwt, List<String> disclosures, String kbJwt,
                Map<String, Object> header, Map<String, Object> payload) {
            this(issuerJwt, disclosures, kbJwt, header, payload, null, null);
        }

        public ParsedToken(String issuerJwt, List<String> disclosures, String kbJwt,
                Map<String, Object> header, Map<String, Object> payload,
                Map<String, Object> verifiedPayload, List<Map<String, Object>> delegateItems) {
            this.issuerJwt = issuerJwt;
            this.disclosures = disclosures;
            this.kbJwt = kbJwt;
            this.header = header;
            this.payload = payload;
            this.verifiedPayload = verifiedPayload;
            this.delegateItems = delegateItems;
        }

        public String getIssuerJwt() { return issuerJwt; }
        public List<String> getDisclosures() { return disclosures; }
        public String getKbJwt() { return kbJwt; }
        public Map<String, Object> getHeader() { return header; }
        public Map<String, Object> getPayload() { return payload; }
        public Map<String, Object> getVerifiedPayload() { return verifiedPayload; }
        public List<Map<String, Object>> getDelegateItems() { return delegateItems; }

        public String getTyp() { return (String) header.get("typ"); }
        public String getSdAlg() { return (String) payload.get("_sd_alg"); }

        public String getSdJwt() {
            if (!disclosures.isEmpty()) {
                return issuerJwt + "~" + String.join("~", disclosures) + "~";
            }
            return issuerJwt + "~";
        }

        public String getCanonical() {
            return kbJwt != null ? getSdJwt() + kbJwt : getSdJwt();
        }

        public ParsedToken withVerifiedPayload(Map<String, Object> payload, List<Map<String, Object>> delegateItems) {
            return new ParsedToken(issuerJwt, disclosures, kbJwt, header, this.payload,
                    payload, delegateItems);
        }

        public ECPublicKey cnfJwk() {
            if (verifiedPayload == null) {
                throw new IllegalStateException("Token has not been verified; cnf.jwk is unavailable");
            }
            Map<String, Object> cnf = findCnf();
            if (cnf == null) return null;
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
            if (jwkMap == null) return null;
            JsonWebKey jwkModel = MAPPER.convertValue(jwkMap, JsonWebKey.class);
            return ecKeyFromJwk(jwkModel);
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> findCnf() {
            if (delegateItems != null) {
                for (Map<String, Object> item : delegateItems) {
                    Map<String, Object> cnf = (Map<String, Object>) item.get("cnf");
                    if (cnf != null && cnf.containsKey("jwk")) return cnf;
                }
            }
            List<Object> delegatePayload = (List<Object>) verifiedPayload.get("delegate_payload");
            if (delegatePayload != null) {
                for (Object item : delegatePayload) {
                    if (!(item instanceof Map)) continue;
                    Map<String, Object> cnf = (Map<String, Object>) ((Map<?, ?>) item).get("cnf");
                    if (cnf != null && cnf.containsKey("jwk")) return cnf;
                }
            }
            Map<String, Object> cnf = (Map<String, Object>) verifiedPayload.get("cnf");
            if (cnf != null && cnf.containsKey("jwk")) return cnf;
            return null;
        }
    }

    // ── Parsing ─────────────────────────────────────────────────────────────

    public static ParsedToken parseToken(String token) {
        if (token.startsWith("~")) throw new IllegalArgumentException("Malformed SD-JWT: empty issuer JWT");
        if (!token.contains("~")) throw new IllegalArgumentException("Malformed SD-JWT: missing disclosure separator");

        String[] parts = token.split("~", -1);
        String issuerJwt = parts[0];
        List<String> disclosureParts = new ArrayList<>();
        for (int i = 1; i < parts.length - 1; i++) {
            disclosureParts.add(parts[i]);
        }
        for (String dp : disclosureParts) {
            if (dp.isEmpty()) throw new IllegalArgumentException("Malformed SD-JWT: empty disclosure segment");
        }

        String kbJwt;
        List<String> disclosures;
        if (token.endsWith("~")) {
            disclosures = disclosureParts;
            kbJwt = null;
        } else {
            String lastPart = parts[parts.length - 1];
            if (lastPart.split("\\.").length != COMPACT_JWT_PARTS) {
                throw new IllegalArgumentException("Malformed KB-JWT: expected header.payload.signature");
            }
            kbJwt = lastPart;
            disclosures = disclosureParts;
        }

        String[] jwtParts = issuerJwt.split("\\.");
        if (jwtParts.length != COMPACT_JWT_PARTS) {
            throw new IllegalArgumentException("Malformed SD-JWT: issuer JWT must have header.payload.signature");
        }
        Map<String, Object> header = decodeJwtSegment(jwtParts[0], "header");
        Map<String, Object> payload = decodeJwtSegment(jwtParts[1], "payload");
        return new ParsedToken(issuerJwt, disclosures, kbJwt, header, payload);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> decodeJwtSegment(String segment, String partName) {
        try {
            byte[] bytes = CryptoUtils.b64urlDecode(segment);
            return MAPPER.readValue(bytes, Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot parse JWT " + partName + ": " + e.getMessage(), e);
        }
    }

    // ── Hashing ──────────────────────────────────────────────────────────────

    private static String hashAscii(String value, String sdAlg) {
        String alg = sdAlg != null ? sdAlg : "sha-256";
        String jdkAlg = HASH_ALGORITHMS.get(alg);
        if (jdkAlg == null) throw new IllegalArgumentException("Unsupported _sd_alg: '" + alg + "'");
        try {
            byte[] digest = MessageDigest.getInstance(jdkAlg).digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return CryptoUtils.b64urlEncode(digest);
        } catch (Exception e) {
            throw new RuntimeException("Hash algorithm not available: " + jdkAlg, e);
        }
    }

    public static String computeSdHash(ParsedToken token) {
        return hashAscii(token.getSdJwt(), token.getSdAlg());
    }

    public static String computeIssuerJwtHash(ParsedToken token) {
        return hashAscii(token.getIssuerJwt(), token.getSdAlg());
    }

    public static String computeDisclosureDigest(String disclosure, String sdAlg) {
        return hashAscii(disclosure, sdAlg);
    }

    // ── Binding ──────────────────────────────────────────────────────────────

    public static Map.Entry<String, String> computeBinding(ParsedToken prevToken, String hashMode) {
        switch (hashMode) {
            case HASH_MODE_SD:
                return Map.entry("sd_hash", computeSdHash(prevToken));
            case HASH_MODE_ISSUER_JWT:
                return Map.entry("issuer_jwt_hash", computeIssuerJwtHash(prevToken));
            default:
                throw new IllegalArgumentException(
                        "hashMode must be 'sd_hash' or 'issuer_jwt_hash', got '" + hashMode + "'");
        }
    }

    public static void verifyBinding(Map<String, Object> payload, ParsedToken prevToken) {
        boolean hasSd = payload.containsKey("sd_hash");
        boolean hasIss = payload.containsKey("issuer_jwt_hash");
        if (hasSd == hasIss) {
            throw new IllegalArgumentException(
                    "KB-SD-JWT payload must contain exactly one of 'sd_hash' or 'issuer_jwt_hash' "
                            + "(got sd_hash=" + hasSd + ", issuer_jwt_hash=" + hasIss + ")");
        }
        if (hasSd) {
            String expected = computeSdHash(prevToken);
            String actual = (String) payload.get("sd_hash");
            if (!expected.equals(actual)) {
                throw new IllegalArgumentException("sd_hash mismatch: expected '" + expected + "', got '" + actual + "'");
            }
        } else {
            String expected = computeIssuerJwtHash(prevToken);
            String actual = (String) payload.get("issuer_jwt_hash");
            if (!expected.equals(actual)) {
                throw new IllegalArgumentException("issuer_jwt_hash mismatch: expected '" + expected + "', got '" + actual + "'");
            }
        }
    }

    // ── Claim helpers ────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> delegateClaimsFromObject(Object payload) {
        Map<String, Object> map = MAPPER.convertValue(payload, Map.class);
        Map<String, Object> filtered = new HashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (entry.getValue() != null) {
                filtered.put(entry.getKey(), entry.getValue());
            }
        }
        return filtered;
    }

    @SuppressWarnings("unchecked")
    public static Map<Object, Object> selectivelyDisclosableClaims(
            Map<String, Object> delegateClaims, DisclosureMetadata sd, Map<String, Object> extraClaims) {
        DisclosureMetadata innerMeta = DisclosureMetadata.ofDiscloseAllAndAllArrayChildren(true, sd);
        DisclosureMetadata outerMeta = DisclosureMetadata.ofChildren(Map.of("delegate_payload", innerMeta));
        Map<String, Object> rawClaims = new HashMap<>();
        rawClaims.put("delegate_payload", List.of(delegateClaims));
        rawClaims.putAll(extraClaims);
        return (Map<Object, Object>) outerMeta.apply(rawClaims);
    }

    public static Map<String, Object> headerParameters(String signingKeyId, String typ) {
        Map<String, Object> params = new HashMap<>();
        if (typ != null) params.put("typ", typ);
        if (signingKeyId != null) params.put("kid", signingKeyId);
        return params;
    }

    public static void verifyExpectedClaims(Map<String, Object> payload, String expectedAud, String expectedNonce, String tokenLabel) {
        if (!payload.containsKey("iat")) {
            throw new IllegalArgumentException(tokenLabel + " missing required 'iat' claim");
        }
        if (expectedAud != null) {
            Object actual = payload.get("aud");
            if (!expectedAud.equals(actual)) {
                throw new IllegalArgumentException(tokenLabel + " aud mismatch: expected '" + expectedAud + "', got '" + actual + "'");
            }
        }
        if (expectedNonce != null) {
            Object actual = payload.get("nonce");
            if (!expectedNonce.equals(actual)) {
                throw new IllegalArgumentException(tokenLabel + " nonce mismatch: expected '" + expectedNonce + "', got '" + actual + "'");
            }
        }
    }

    // ── Key helpers ──────────────────────────────────────────────────────────

    static ECPublicKey ecKeyFromJwk(JsonWebKey jwk) {
        if (jwk.x() == null) throw new IllegalArgumentException("JWK missing x coordinate");
        if (jwk.y() == null) throw new IllegalArgumentException("JWK missing y coordinate");
        try {
            return new ECKey.Builder(Curve.P_256, new Base64URL(jwk.x()), new Base64URL(jwk.y()))
                    .build()
                    .toECPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build EC key from JWK", e);
        }
    }
}