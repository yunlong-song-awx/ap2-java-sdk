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
import com.airwallex.ap2.KbSdJwt;
import com.airwallex.ap2.SdJwt;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SdJwtChain {
    private SdJwtChain() {
    }

    private static final Logger logger = LoggerFactory.getLogger(SdJwtChain.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final int DISCLOSURE_ARRAY_LEN = 2;
    private static final int DISCLOSURE_PROPERTY_LEN = 3;

    @FunctionalInterface
    public interface PublicKeyProvider {
        ECPublicKey resolve(SdJwtCommon.ParsedToken token);
    }

    public static List<Map<String, Object>> verifyChain(
            List<SdJwtCommon.ParsedToken> tokens,
            PublicKeyProvider publicKeyProvider,
            int clockSkewSeconds,
            String expectedAud,
            String expectedNonce,
            Long currentTime) {
        if (tokens.isEmpty()) throw new IllegalArgumentException("Tokens list cannot be empty");

        List<SdJwtCommon.ParsedToken> parsedTokens = new ArrayList<>(tokens);
        long now = currentTime != null ? currentTime : System.currentTimeMillis() / 1000L;
        List<Map<String, Object>> payloads = new ArrayList<>();

        SdJwtCommon.ParsedToken rootToken = parsedTokens.get(0);
        ECPublicKey rootKey = publicKeyProvider.resolve(rootToken);
        Map<String, Object> rootPayload = SdJwt.verify(rootToken.getCanonical(), rootKey);
        List<Map<String, Object>> rootItems = effectivePayloads(rootPayload, rootToken, 0, true);
        parsedTokens.set(0, rootToken.withVerifiedPayload(rootPayload, rootItems));
        checkTimeClaims(List.of(rootPayload), 0, now, clockSkewSeconds);
        checkTimeClaims(rootItems, 0, now, clockSkewSeconds);
        if (!rootItems.isEmpty()) {
            payloads.addAll(rootItems);
        } else {
            payloads.add(rootPayload);
        }

        for (int i = 1; i < parsedTokens.size(); i++) {
            boolean isLast = i == parsedTokens.size() - 1;
            SdJwtCommon.ParsedToken currentToken = parsedTokens.get(i);
            Map<String, Object> hopPayload = KbSdJwt.verify(
                    currentToken, parsedTokens.get(i - 1),
                    isLast ? expectedAud : null,
                    isLast ? expectedNonce : null);
            List<Map<String, Object>> delegateItems = effectivePayloads(hopPayload, currentToken, i, !isLast);
            checkTimeClaims(List.of(hopPayload), i, now, clockSkewSeconds);
            checkTimeClaims(delegateItems, i, now, clockSkewSeconds);
            if (!delegateItems.isEmpty()) {
                payloads.addAll(delegateItems);
            } else {
                payloads.add(hopPayload);
            }
            parsedTokens.set(i, currentToken.withVerifiedPayload(hopPayload, delegateItems));
        }

        return payloads;
    }

    private static List<Map<String, Object>> effectivePayloads(
            Map<String, Object> payload, SdJwtCommon.ParsedToken token, int tokenIndex, boolean requireSingle) {
        List<Map<String, Object>> items = resolveDelegateItems(payload.get("delegate_payload"), token, tokenIndex);
        if (requireSingle && items.size() > 1) {
            throw new IllegalStateException("Token " + tokenIndex
                    + ": delegate_payload has " + items.size() + " disclosed items, expected exactly 1");
        }
        return items;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> resolveDelegateItems(
            Object delegatePayload, SdJwtCommon.ParsedToken token, int tokenIndex) {
        if (!(delegatePayload instanceof List)) return List.of();
        List<Object> dpList = (List<Object>) delegatePayload;
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : dpList) {
            if (item instanceof Map) {
                Map<String, Object> mutableItem = new HashMap<>((Map<String, Object>) item);
                inlineSdClaims(mutableItem, token);
                result.add(mutableItem);
            } else if (item instanceof String) {
                Map<String, Object> decoded = decodeDisclosureDict((String) item, tokenIndex);
                if (decoded != null) result.add(decoded);
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static void inlineSdClaims(Map<String, Object> item, SdJwtCommon.ParsedToken token) {
        List<String> sdDigests = (List<String>) item.get("_sd");
        if (sdDigests == null || token.getDisclosures().isEmpty()) return;
        for (String digest : sdDigests) {
            for (String disc : token.getDisclosures()) {
                if (!digest.equals(SdJwtCommon.computeDisclosureDigest(disc, token.getSdAlg()))) continue;
                try {
                    byte[] bytes = CryptoUtils.b64urlDecode(disc);
                    List<Object> arr = mapper.readValue(bytes, List.class);
                    if (arr.size() == DISCLOSURE_PROPERTY_LEN) {
                        item.put((String) arr.get(1), arr.get(2));
                    }
                    break;
                } catch (Exception e) {
                    break;
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeDisclosureDict(String disclosure, int tokenIndex) {
        try {
            byte[] bytes = CryptoUtils.b64urlDecode(disclosure);
            List<Object> arr = mapper.readValue(bytes, List.class);
            Object value = switch (arr.size()) {
                case DISCLOSURE_PROPERTY_LEN -> arr.get(2);
                case DISCLOSURE_ARRAY_LEN -> arr.get(1);
                default -> null;
            };
            return (Map<String, Object>) value;
        } catch (Exception e) {
            logger.warn("Token {}: Failed to decode disclosure in delegate_payload: {}", tokenIndex, e.getMessage());
            return null;
        }
    }

    private static void checkTimeClaims(List<Map<String, Object>> payloads, int tokenIndex, long now, int clockSkew) {
        for (Map<String, Object> p : payloads) {
            Object exp = p.get("exp");
            if (exp != null) {
                long expVal = ((Number) exp).longValue();
                if (now > expVal + clockSkew) {
                    throw new IllegalArgumentException("Token " + tokenIndex + " expired at " + expVal);
                }
            }
            Object iat = p.get("iat");
            if (iat != null) {
                long iatVal = ((Number) iat).longValue();
                if (iatVal > now + clockSkew) {
                    throw new IllegalArgumentException("Token " + tokenIndex + " iat is in the future: " + iatVal);
                }
            }
            Object nbf = p.get("nbf");
            if (nbf != null) {
                long nbfVal = ((Number) nbf).longValue();
                if (nbfVal > now + clockSkew) {
                    throw new IllegalArgumentException("Token " + tokenIndex + " not valid before " + nbfVal);
                }
            }
        }
    }
}