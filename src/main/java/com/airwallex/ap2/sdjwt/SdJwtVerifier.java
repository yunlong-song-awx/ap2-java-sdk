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
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public class SdJwtVerifier {
    private final ObjectMapper mapper = new ObjectMapper();
    private final SdJwtCommon.ParsedToken parsed;
    private final BiFunction<String, Map<String, Object>, ECPublicKey> issuerKeyProvider;
    private final String expectedAud;
    private final String expectedNonce;
    private final Supplier<Map<String, Object>> verifiedPayloadSupplier;

    public SdJwtVerifier(String sdJwtString,
            BiFunction<String, Map<String, Object>, ECPublicKey> issuerKeyProvider,
            String expectedAud, String expectedNonce) {
        this.parsed = SdJwtCommon.parseToken(sdJwtString);
        this.issuerKeyProvider = issuerKeyProvider;
        this.expectedAud = expectedAud;
        this.expectedNonce = expectedNonce;
        this.verifiedPayloadSupplier = () -> {
            try {
                JWSObject jwsObject = JWSObject.parse(parsed.getIssuerJwt());
                String issuer = (String) parsed.getPayload().get("iss");
                ECPublicKey publicKey = issuerKeyProvider.apply(issuer, parsed.getHeader());
                if (!jwsObject.verify(new ECDSAVerifier(publicKey))) {
                    throw new IllegalArgumentException("SD-JWT signature verification failed");
                }
                Map<String, List<Object>> disclosureMap = buildDisclosureMap(parsed.getDisclosures(), parsed.getSdAlg());
                @SuppressWarnings("unchecked")
                Map<String, Object> resolved = (Map<String, Object>) resolvePayload(
                        new HashMap<>(parsed.getPayload()), disclosureMap);
                if (expectedAud != null && !expectedAud.equals(resolved.get("aud"))) {
                    throw new IllegalArgumentException("SD-JWT aud mismatch: expected '"
                            + expectedAud + "', got '" + resolved.get("aud") + "'");
                }
                if (expectedNonce != null && !expectedNonce.equals(resolved.get("nonce"))) {
                    throw new IllegalArgumentException("SD-JWT nonce mismatch: expected '"
                            + expectedNonce + "', got '" + resolved.get("nonce") + "'");
                }
                return resolved;
            } catch (Exception e) {
                throw new RuntimeException("SD-JWT verification failed", e);
            }
        };
    }

    public Map<String, Object> getVerifiedPayload() {
        return verifiedPayloadSupplier.get();
    }

    private Map<String, List<Object>> buildDisclosureMap(List<String> disclosures, String sdAlg) {
        Map<String, List<Object>> map = new HashMap<>();
        for (String disc : disclosures) {
            String digest = SdJwtCommon.computeDisclosureDigest(disc, sdAlg);
            byte[] bytes = CryptoUtils.b64urlDecode(disc);
            try {
                @SuppressWarnings("unchecked")
                List<Object> arr = mapper.readValue(bytes, List.class);
                map.put(digest, arr);
            } catch (Exception ignored) {
            }
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private Object resolvePayload(Object data, Map<String, List<Object>> disclosureMap) {
        if (data instanceof Map<?, ?> map) {
            Map<String, Object> result = (Map<String, Object>) new HashMap<>(map);
            List<Object> sdDigests = (List<Object>) result.remove("_sd");
            if (sdDigests != null) {
                for (Object digest : sdDigests) {
                    if (!(digest instanceof String)) continue;
                    List<Object> arr = disclosureMap.get((String) digest);
                    if (arr == null || arr.size() != 3) continue;
                    String name = (String) arr.get(1);
                    if (name == null) continue;
                    result.put(name, resolvePayload(arr.get(2), disclosureMap));
                }
            }
            for (Map.Entry<String, Object> e : result.entrySet()) {
                e.setValue(resolvePayload(e.getValue(), disclosureMap));
            }
            return result;
        }
        if (data instanceof List<?> list) {
            List<Object> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> itemMap) {
                    String digest = (String) itemMap.get("...");
                    if (digest != null) {
                        List<Object> arr = disclosureMap.get(digest);
                        if (arr != null && arr.size() == 2) {
                            result.add(resolvePayload(arr.get(1), disclosureMap));
                            continue;
                        }
                        continue;
                    }
                }
                result.add(resolvePayload(item, disclosureMap));
            }
            return result;
        }
        return data;
    }
}