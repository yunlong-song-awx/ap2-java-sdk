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

package com.airwallex.ap2.mandate;

import com.airwallex.ap2.CryptoUtils;
import com.airwallex.ap2.KbSdJwt;
import com.airwallex.ap2.SdJwt;
import com.airwallex.ap2.sdjwt.DisclosureMetadata;
import com.airwallex.ap2.sdjwt.SdJwtChain;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.airwallex.ap2.sdjwt.SdJwtHolder;
import com.airwallex.ap2.sdjwt.SdJwtIssuer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MandateClient {
    private static final Logger logger = LoggerFactory.getLogger(MandateClient.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final int COMPACT_JWT_PARTS = 3;
    private static final Path LOG_FILE_PATH = Paths.get(
            System.getProperty("user.home"), ".logs", "ap2", "mandate_operations.log");

    public String create(List<Object> payloads, ECPrivateKey issuerKey, String issuerKeyId,
            DisclosureMetadata sd, ECPublicKey holderPublicKey, Map<String, Object> extraClaims) {
        if (payloads.isEmpty()) throw new IllegalArgumentException("payloads list cannot be empty");
        Map<String, Object> cnfClaims = holderPublicKey != null
                ? Map.of("cnf", ecPublicKeyToCnfClaim(holderPublicKey)) : Map.of();
        Map<String, Object> allExtra = new java.util.HashMap<>(cnfClaims);
        if (extraClaims != null) allExtra.putAll(extraClaims);
        SdJwtIssuer issuer = SdJwt.create(payloads.get(0), issuerKey, issuerKeyId, sd, false, allExtra);
        return issuer.getSdJwtIssuance();
    }

    public String create(List<Object> payloads, ECPrivateKey issuerKey) {
        return create(payloads, issuerKey, null, null, null, null);
    }

    public String create(List<Object> payloads, ECPrivateKey issuerKey, DisclosureMetadata sd) {
        return create(payloads, issuerKey, null, sd, null, null);
    }

    public List<Map<String, Object>> verify(String token, Object keyOrProvider,
            String expectedAud, String expectedNonce, int clockSkewSeconds, Long currentTime) {
        String[] segments = token.split("~~", -1);
        boolean isSingle = segments.length == 1;

        SdJwtChain.PublicKeyProvider publicKeyProvider;
        if (isSingle) {
            if (!(keyOrProvider instanceof ECPublicKey)) {
                throw new IllegalArgumentException(
                        "Single mandate verification requires an ECPublicKey; got "
                                + keyOrProvider.getClass().getSimpleName());
            }
            ECPublicKey key = (ECPublicKey) keyOrProvider;
            publicKeyProvider = token1 -> key;
        } else {
            if (!(keyOrProvider instanceof SdJwtChain.PublicKeyProvider)) {
                throw new IllegalArgumentException(
                        "Chain verification requires a PublicKeyProvider; got "
                                + keyOrProvider.getClass().getSimpleName());
            }
            publicKeyProvider = (SdJwtChain.PublicKeyProvider) keyOrProvider;
        }

        List<SdJwtCommon.ParsedToken> parsedTokens = new ArrayList<>();
        for (int i = 0; i < segments.length; i++) {
            parsedTokens.add(SdJwtCommon.parseToken(canonicalChainSegment(segments[i], i, segments.length)));
        }

        logger.debug("verify: mode={}, numTokens={}", isSingle ? "single" : "chain", segments.length);

        logEvent("verify", "before", Map.of(
                "mode", isSingle ? "single" : "chain",
                "numTokens", segments.length,
                "hasAud", expectedAud != null,
                "hasNonce", expectedNonce != null));

        List<Map<String, Object>> payloads = SdJwtChain.verifyChain(parsedTokens, publicKeyProvider,
                clockSkewSeconds, expectedAud, expectedNonce, currentTime);

        logEvent("verify", "after", Map.of("success", true, "numPayloads", payloads.size()));

        return payloads;
    }

    public String present(ECPrivateKey holderKey, String mandateToken, List<Object> payloads,
            String holderKeyId, DisclosureMetadata sd, Map<String, Object> claimsToDisclose,
            String nonce, String aud, String hashMode) {
        if (payloads.isEmpty()) throw new IllegalArgumentException("payloads list cannot be empty");

        String redactedOpenTok;
        Map<String, Object> claimsForHolder;

        if (claimsToDisclose != null) {
            SdJwtHolder holder = new SdJwtHolder(mandateToken);
            List<String> selected = new ArrayList<>();
            for (String disc : holder.getInputDisclosures()) {
                try {
                    @SuppressWarnings("unchecked")
                    List<Object> decoded = mapper.readValue(CryptoUtils.b64urlDecode(disc), List.class);
                    if (decoded.size() == 2) {
                        Object value = decoded.get(1);
                        if (value instanceof Map<?, ?> valueMap && valueMap.containsKey("vct")) {
                            selected.add(disc);
                        }
                    } else if (decoded.size() == 3) {
                        String key = (String) decoded.get(1);
                        if ("cnf".equals(key) || claimsToDisclose.containsKey(key)) {
                            selected.add(disc);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            String jwtPart = mandateToken.split("~", 2)[0];
            redactedOpenTok = jwtPart + "~" + String.join("~", selected) + "~";
            claimsForHolder = Map.of("delegate_payload", List.of(claimsToDisclose));
        } else {
            redactedOpenTok = null;
            claimsForHolder = Map.of("delegate_payload", List.of(DisclosureMetadata.sdClaimsToDisclose(payloads.get(0))));
        }

        String prevTokenForBinding = redactedOpenTok != null ? redactedOpenTok : mandateToken;
        SdJwtCommon.ParsedToken prevTokenParsed = SdJwtCommon.parseToken(prevTokenForBinding);

        SdJwtIssuer issuer = KbSdJwt.create(prevTokenParsed, holderKey, payloads.get(0),
                aud, nonce, holderKeyId, sd, hashMode, false);

        SdJwtHolder holderForPresentation = new SdJwtHolder(issuer.getSdJwtIssuance());
        holderForPresentation.createPresentation(claimsForHolder);
        String presJwt = holderForPresentation.getSdJwtPresentation();

        if (redactedOpenTok != null) {
            String openTokJoined = redactedOpenTok.replaceAll("~+$", "");
            return openTokJoined + "~~" + presJwt;
        } else {
            String mandateTokJoined = mandateToken.replaceAll("~+$", "");
            return mandateTokJoined + "~~" + presJwt;
        }
    }

    public String getClosedMandateJwt(String presentationToken) {
        int lastSep = presentationToken.lastIndexOf("~~");
        String lastSegment = lastSep >= 0 ? presentationToken.substring(lastSep + 2) : presentationToken;
        int tilde = lastSegment.indexOf("~");
        return tilde >= 0 ? lastSegment.substring(0, tilde) : lastSegment;
    }

    private String canonicalChainSegment(String segment, int index, int total) {
        if (index == total - 1 || segment.endsWith("~")) return segment;
        String lastPart = segment.contains("~") ? segment.substring(segment.lastIndexOf("~") + 1) : segment;
        if (lastPart.split("\\.").length == COMPACT_JWT_PARTS) return segment;
        return segment + "~";
    }

    private Map<String, Object> ecPublicKeyToCnfClaim(ECPublicKey key) {
        try {
            ECKey ecKey = new ECKey.Builder(Curve.P_256, key).build();
            return Map.of("jwk", Map.of(
                    "kty", "EC",
                    "crv", "P-256",
                    "x", ecKey.getX().toString(),
                    "y", ecKey.getY().toString()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert EC key to JWK", e);
        }
    }

    private void logEvent(String eventType, String stage, Map<String, Object> data) {
        Map<String, Object> logEntry = new HashMap<>();
        logEntry.put("timestamp", Instant.now().toString());
        logEntry.put("event", eventType);
        logEntry.put("stage", stage);
        logEntry.put("data", data);
        try {
            Files.createDirectories(LOG_FILE_PATH.getParent());
            String line = mapper.writeValueAsString(logEntry) + "\n";
            Files.writeString(LOG_FILE_PATH, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            logger.warn("Failed to write to mandate log file: {}", e.getMessage());
        }
    }
}