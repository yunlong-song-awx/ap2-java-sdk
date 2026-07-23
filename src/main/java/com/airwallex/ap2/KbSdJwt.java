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

import com.airwallex.ap2.sdjwt.DisclosureMetadata;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.airwallex.ap2.sdjwt.SdJwtIssuer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class KbSdJwt {
    private KbSdJwt() {
    }

    public static final List<String> TYP_TERMINAL = List.of("kb+sd-jwt", "kb-sd-jwt");
    public static final List<String> TYP_INTERMEDIATE = List.of("kb+sd-jwt+kb", "kb-sd-jwt+kb");

    private static final ObjectMapper mapper = new ObjectMapper();

    public static SdJwtIssuer create(SdJwtCommon.ParsedToken prevToken, ECPrivateKey holderKey,
            Object payload, String aud, String nonce, String holderKeyId,
            DisclosureMetadata sd, String hashMode, boolean addDecoyClaims) {
        if (aud == null || aud.isBlank() || nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("aud and nonce are required for KB-SD-JWT hops");
        }

        Map<String, Object> delegateClaims = SdJwtCommon.delegateClaimsFromObject(payload);
        boolean hasCnf = delegateClaims.containsKey("cnf");
        DisclosureMetadata resolvedSd = sd != null ? sd : null;

        Map.Entry<String, String> binding = SdJwtCommon.computeBinding(prevToken, hashMode);
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("iat", System.currentTimeMillis() / 1000L);
        extraClaims.put("aud", aud);
        extraClaims.put("nonce", nonce);
        extraClaims.put(binding.getKey(), binding.getValue());

        boolean terminal = !hasCnf;
        String typ = terminal ? TYP_TERMINAL.get(0) : TYP_INTERMEDIATE.get(0);

        Map<Object, Object> sdClaims = SdJwtCommon.selectivelyDisclosableClaims(delegateClaims, resolvedSd, extraClaims);
        return new SdJwtIssuer(sdClaims, holderKey, holderKeyId, addDecoyClaims,
                SdJwtCommon.headerParameters(holderKeyId, typ));
    }

    public static Map<String, Object> verify(SdJwtCommon.ParsedToken token, SdJwtCommon.ParsedToken prevToken,
            String expectedAud, String expectedNonce) {
        String typ = token.getTyp();
        List<String> knownTypes = new ArrayList<>();
        knownTypes.addAll(TYP_TERMINAL);
        knownTypes.addAll(TYP_INTERMEDIATE);
        if (!knownTypes.contains(typ)) {
            throw new IllegalArgumentException(
                    "Unexpected JWT typ: expected one of " + knownTypes + ", got '" + typ + "'");
        }

        ECPublicKey prevKey = prevToken.cnfJwk();
        if (prevKey == null) throw new IllegalStateException("Previous token missing cnf.jwk");
        Map<String, Object> payload = SdJwt.verify(token.getCanonical(), prevKey);

        resolveDelegatePayload(payload, token);
        SdJwtCommon.verifyBinding(payload, prevToken);

        if (TYP_TERMINAL.contains(typ)) {
            SdJwtCommon.verifyExpectedClaims(payload, expectedAud, expectedNonce, "KB-SD-JWT");
        }

        boolean hasCnf = delegatePayloadHasCnf(payload);
        if (TYP_TERMINAL.contains(typ) && hasCnf) {
            throw new IllegalStateException("Terminal KB-SD-JWT MUST NOT carry a 'cnf' claim");
        }
        if (TYP_INTERMEDIATE.contains(typ) && !hasCnf) {
            throw new IllegalStateException("Intermediate " + typ + " requires a 'cnf' claim");
        }
        return payload;
    }

    private static boolean delegatePayloadHasCnf(Map<String, Object> payload) {
        @SuppressWarnings("unchecked")
        List<Object> dp = (List<Object>) payload.get("delegate_payload");
        if (dp == null) return false;
        return dp.stream().anyMatch(item -> item instanceof Map<?, ?> && ((Map<?, ?>) item).get("cnf") instanceof Map);
    }

    @SuppressWarnings("unchecked")
    private static void resolveDelegatePayload(Map<String, Object> payload, SdJwtCommon.ParsedToken token) {
        List<Object> dp = (List<Object>) payload.get("delegate_payload");
        if (dp == null || token.getDisclosures().isEmpty()) return;
        String sdAlg = token.getSdAlg();
        List<Object> resolved = new ArrayList<>();
        for (Object item : dp) {
            if (item instanceof String) {
                Map<String, Object> resolved2 = tryResolveDigest((String) item, token.getDisclosures(), sdAlg);
                resolved.add(resolved2 != null ? resolved2 : item);
            } else {
                resolved.add(item);
            }
        }
        payload.put("delegate_payload", resolved);
    }

    private static Map<String, Object> tryResolveDigest(String digest, List<String> disclosures, String sdAlg) {
        for (String disc : disclosures) {
            if (!SdJwtCommon.computeDisclosureDigest(disc, sdAlg).equals(digest)) continue;
            try {
                byte[] bytes = CryptoUtils.b64urlDecode(disc);
                @SuppressWarnings("unchecked")
                List<Object> arr = mapper.readValue(bytes, List.class);
                Object value = switch (arr.size()) {
                    case 2 -> arr.get(1);
                    case 3 -> arr.get(2);
                    default -> null;
                };
                if (value instanceof Map) {
                    return (Map<String, Object>) value;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }
}