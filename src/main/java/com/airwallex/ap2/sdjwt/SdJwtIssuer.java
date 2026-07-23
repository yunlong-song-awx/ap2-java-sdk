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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SdJwtIssuer {
    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<String> collectedDisclosures = new ArrayList<>();
    private final String sdJwtIssuance;

    @SuppressWarnings("unchecked")
    public SdJwtIssuer(Map<Object, Object> userClaims, ECPrivateKey issuerKey, String issuerKeyId,
            boolean addDecoyClaims, Map<String, Object> extraHeaderParameters) {
        try {
            Map<String, Object> processedClaims = processClaims(userClaims);
            processedClaims.put("_sd_alg", "sha-256");
            if (addDecoyClaims) addDecoys(processedClaims);

            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256);
            if (issuerKeyId != null) headerBuilder.keyID(issuerKeyId);
            for (Map.Entry<String, Object> e : extraHeaderParameters.entrySet()) {
                String k = e.getKey();
                Object v = e.getValue();
                switch (k) {
                    case "kid" -> headerBuilder.keyID((String) v);
                    case "typ" -> headerBuilder.type(new JOSEObjectType((String) v));
                    case "alg" -> {}
                    default -> headerBuilder.customParam(k, v);
                }
            }
            JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(mapper.writeValueAsString(processedClaims)));
            jwsObject.sign(new ECDSASigner(issuerKey));
            String issuerJwt = jwsObject.serialize();

            if (!collectedDisclosures.isEmpty()) {
                sdJwtIssuance = issuerJwt + "~" + String.join("~", collectedDisclosures) + "~";
            } else {
                sdJwtIssuance = issuerJwt + "~";
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SD-JWT issuance", e);
        }
    }

    public String getSdJwtIssuance() {
        return sdJwtIssuance;
    }

    // ── Recursive claim processing ───────────────────────────────────────

    @SuppressWarnings("unchecked")
    private Map<String, Object> processClaims(Map<Object, Object> claims) {
        Map<String, Object> result = new HashMap<>();
        List<String> sdDigests = new ArrayList<>();

        for (Map.Entry<Object, Object> entry : claims.entrySet()) {
            if (entry.getKey() instanceof SdObject<?> sdObj) {
                String keyName = (String) sdObj.wrapped();
                Object processedValue = processValue(entry.getValue());
                String disclosure = createPropertyDisclosure(keyName, processedValue);
                sdDigests.add(SdJwtCommon.computeDisclosureDigest(disclosure, "sha-256"));
                collectedDisclosures.add(disclosure);
            } else if (entry.getKey() instanceof String) {
                result.put((String) entry.getKey(), processValue(entry.getValue()));
            } else {
                throw new IllegalArgumentException("Unexpected key type: " + entry.getKey().getClass().getSimpleName());
            }
        }

        if (!sdDigests.isEmpty()) {
            Collections.shuffle(sdDigests, random);
            result.put("_sd", sdDigests);
        }
        return result;
    }

    private List<Object> processList(List<?> list) {
        List<Object> result = new ArrayList<>();
        for (Object element : list) {
            if (element instanceof SdObject<?> sdObj) {
                Object processedValue = processValue(sdObj.wrapped());
                String disclosure = createArrayDisclosure(processedValue);
                String digest = SdJwtCommon.computeDisclosureDigest(disclosure, "sha-256");
                collectedDisclosures.add(disclosure);
                result.add(Map.of("...", digest));
            } else {
                result.add(processValue(element));
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Object processValue(Object value) {
        if (value instanceof Map<?, ?>) {
            return processClaims((Map<Object, Object>) value);
        }
        if (value instanceof List<?>) {
            return processList((List<?>) value);
        }
        return value;
    }

    // ── Disclosure construction ──────────────────────────────────────────

    private String randomSalt() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return CryptoUtils.b64urlEncode(salt);
    }

    private String createPropertyDisclosure(String name, Object value) {
        try {
            List<Object> arr = List.of(randomSalt(), name, value);
            return CryptoUtils.b64urlEncode(mapper.writeValueAsBytes(arr));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create property disclosure", e);
        }
    }

    private String createArrayDisclosure(Object value) {
        try {
            List<Object> arr = List.of(randomSalt(), value);
            return CryptoUtils.b64urlEncode(mapper.writeValueAsBytes(arr));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create array disclosure", e);
        }
    }

    // ── Decoy claims ─────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void addDecoys(Map<String, Object> payload) {
        int decoyCount = random.nextInt(3) + 1;
        List<String> existing = (List<String>) payload.get("_sd");
        if (existing == null) {
            existing = new ArrayList<>();
            payload.put("_sd", existing);
        }
        for (int i = 0; i < decoyCount; i++) {
            byte[] fakeBytes = new byte[32];
            random.nextBytes(fakeBytes);
            String fakeDisclosure = CryptoUtils.b64urlEncode(fakeBytes);
            existing.add(SdJwtCommon.computeDisclosureDigest(fakeDisclosure, "sha-256"));
        }
        Collections.shuffle(existing, random);
    }
}