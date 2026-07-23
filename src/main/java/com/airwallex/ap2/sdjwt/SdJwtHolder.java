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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SdJwtHolder {
    private final ObjectMapper mapper = new ObjectMapper();
    private final SdJwtCommon.ParsedToken parsed;
    private final List<String> inputDisclosures;
    private String sdJwtPresentation = "";

    public SdJwtHolder(String sdJwtIssuance) {
        this.parsed = SdJwtCommon.parseToken(sdJwtIssuance);
        this.inputDisclosures = parsed.getDisclosures();
    }

    public List<String> getInputDisclosures() {
        return inputDisclosures;
    }

    public String getSdJwtPresentation() {
        return sdJwtPresentation;
    }

    public void createPresentation(Map<String, Object> claimsToDisclose) {
        List<String> selectedDisclosures = selectDisclosures(claimsToDisclose);
        if (!selectedDisclosures.isEmpty()) {
            sdJwtPresentation = parsed.getIssuerJwt() + "~" + String.join("~", selectedDisclosures) + "~";
        } else {
            sdJwtPresentation = parsed.getIssuerJwt() + "~";
        }
    }

    private List<String> selectDisclosures(Map<String, Object> claimsToDisclose) {
        List<String> selected = new ArrayList<>();
        for (String disc : inputDisclosures) {
            List<Object> arr = decodeDisclosure(disc);
            if (arr == null) continue;
            if (arr.size() == 3) {
                String name = (String) arr.get(1);
                if (name != null && claimsToDisclose.containsKey(name)) {
                    selected.add(disc);
                }
            } else if (arr.size() == 2) {
                Object value = arr.get(1);
                if (shouldIncludeArrayElement(value, claimsToDisclose)) {
                    selected.add(disc);
                }
            }
        }
        return selected;
    }

    private boolean shouldIncludeArrayElement(Object value, Map<String, Object> claimsToDisclose) {
        if (value instanceof Map<?, ?> valueMap) {
            if (valueMap.containsKey("vct")) return true;
            return valueMap.keySet().stream().anyMatch(claimsToDisclose::containsKey);
        }
        return claimsToDisclose.values().stream().anyMatch(v -> Boolean.TRUE.equals(v));
    }

    private List<Object> decodeDisclosure(String disc) {
        try {
            byte[] bytes = CryptoUtils.b64urlDecode(disc);
            @SuppressWarnings("unchecked")
            List<Object> result = mapper.readValue(bytes, List.class);
            return result;
        } catch (Exception e) {
            return null;
        }
    }
}