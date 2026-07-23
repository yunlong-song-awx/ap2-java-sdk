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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DisclosureMetadata {
    private final List<String> sdKeys;
    private final List<Integer> sdArrayIndices;
    private final boolean discloseAll;
    private final Map<String, DisclosureMetadata> children;
    private final Map<Integer, DisclosureMetadata> arrayChildren;
    private final DisclosureMetadata allArrayChildren;

    public DisclosureMetadata() {
        this(List.of(), List.of(), false, Map.of(), Map.of(), null);
    }

    public DisclosureMetadata(List<String> sdKeys, List<Integer> sdArrayIndices,
            boolean discloseAll, Map<String, DisclosureMetadata> children,
            Map<Integer, DisclosureMetadata> arrayChildren, DisclosureMetadata allArrayChildren) {
        this.sdKeys = sdKeys != null ? sdKeys : List.of();
        this.sdArrayIndices = sdArrayIndices != null ? sdArrayIndices : List.of();
        this.discloseAll = discloseAll;
        this.children = children != null ? children : Map.of();
        this.arrayChildren = arrayChildren != null ? arrayChildren : Map.of();
        this.allArrayChildren = allArrayChildren;
    }

    public List<String> getSdKeys() { return sdKeys; }
    public List<Integer> getSdArrayIndices() { return sdArrayIndices; }
    public boolean isDiscloseAll() { return discloseAll; }
    public Map<String, DisclosureMetadata> getChildren() { return children; }
    public Map<Integer, DisclosureMetadata> getArrayChildren() { return arrayChildren; }
    public DisclosureMetadata getAllArrayChildren() { return allArrayChildren; }

    public static DisclosureMetadata ofDiscloseAll(boolean discloseAll) {
        return new DisclosureMetadata(List.of(), List.of(), discloseAll, Map.of(), Map.of(), null);
    }

    public static DisclosureMetadata ofChildren(Map<String, DisclosureMetadata> children) {
        return new DisclosureMetadata(List.of(), List.of(), false, children, Map.of(), null);
    }

    public static DisclosureMetadata ofAllArrayChildren(DisclosureMetadata allArrayChildren) {
        return new DisclosureMetadata(List.of(), List.of(), false, Map.of(), Map.of(), allArrayChildren);
    }

    public static DisclosureMetadata ofDiscloseAllAndAllArrayChildren(boolean discloseAll, DisclosureMetadata allArrayChildren) {
        return new DisclosureMetadata(List.of(), List.of(), discloseAll, Map.of(), Map.of(), allArrayChildren);
    }

    public static DisclosureMetadata ofSdKeys(List<String> sdKeys) {
        return new DisclosureMetadata(sdKeys, List.of(), false, Map.of(), Map.of(), null);
    }

    public static DisclosureMetadata fromDict(Map<String, Object> data) {
        if (data.isEmpty()) return new DisclosureMetadata();

        @SuppressWarnings("unchecked")
        Map<String, Object> childrenRaw = (Map<String, Object>) data.getOrDefault("children", Map.of());
        Map<String, DisclosureMetadata> children = new HashMap<>();
        for (Map.Entry<String, Object> e : childrenRaw.entrySet()) {
            if (e.getValue() instanceof Map) {
                children.put(e.getKey(), fromDict((Map<String, Object>) e.getValue()));
            }
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> arrayChildrenRaw = (Map<String, Object>) data.getOrDefault("array_children", Map.of());
        Map<Integer, DisclosureMetadata> arrayChildren = new HashMap<>();
        for (Map.Entry<String, Object> e : arrayChildrenRaw.entrySet()) {
            int idx = Integer.parseInt(e.getKey());
            if (e.getValue() instanceof Map) {
                arrayChildren.put(idx, fromDict((Map<String, Object>) e.getValue()));
            }
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> allArrayChildrenRaw = (Map<String, Object>) data.get("all_array_children");
        DisclosureMetadata allArrayChildren = allArrayChildrenRaw != null ? fromDict(allArrayChildrenRaw) : null;

        @SuppressWarnings("unchecked")
        List<String> sdKeysVal = (List<String>) data.getOrDefault("sd_keys", List.of());
        @SuppressWarnings("unchecked")
        List<Integer> sdArrayIndicesVal = (List<Integer>) data.getOrDefault("sd_array_indices", List.of());
        boolean discloseAllVal = (Boolean) data.getOrDefault("disclose_all", false);
        return new DisclosureMetadata(sdKeysVal, sdArrayIndicesVal, discloseAllVal,
                children, arrayChildren, allArrayChildren);
    }

    @SuppressWarnings("unchecked")
    public Object apply(Object data) {
        if (data instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) data;
            Map<Object, Object> result = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String k = entry.getKey();
                Object v = entry.getValue();
                DisclosureMetadata childMeta = children.get(k);
                Object processedV = childMeta != null ? childMeta.apply(v) : v;
                if (discloseAll || sdKeys.contains(k)) {
                    result.put(new SdObject<>(k), processedV);
                } else {
                    result.put(k, processedV);
                }
            }
            return result;
        } else if (data instanceof List) {
            List<Object> list = (List<Object>) data;
            List<Object> result = new ArrayList<>();
            for (int i = 0; i < list.size(); i++) {
                DisclosureMetadata childMeta = arrayChildren.getOrDefault(i, allArrayChildren);
                Object processedItem = childMeta != null ? childMeta.apply(list.get(i)) : list.get(i);
                if (discloseAll || sdArrayIndices.contains(i)) {
                    result.add(new SdObject<>(processedItem));
                } else {
                    result.add(processedItem);
                }
            }
            return result;
        }
        return data;
    }

    public static Map<String, Object> sdClaimsToDisclose(Object obj) {
        Map<String, Object> result = new HashMap<>();
        var kClass = obj.getClass();
        for (var field : kClass.getDeclaredFields()) {
            SelectivelyDisclosable sd = field.getAnnotation(SelectivelyDisclosable.class);
            Object value;
            try {
                field.setAccessible(true);
                value = field.get(obj);
            } catch (Exception e) {
                value = null;
            }
            String name = field.getName();

            if (sd != null && sd.field()) {
                result.put(name, true);
                continue;
            }
            if (sd != null && sd.array()) {
                if (value instanceof List<?>) {
                    List<Boolean> list = new ArrayList<>();
                    for (int i = 0; i < ((List<?>) value).size(); i++) {
                        list.add(true);
                    }
                    result.put(name, list);
                }
                continue;
            }
            if (value != null && !(value instanceof String) && !(value instanceof Number) && !(value instanceof Boolean)) {
                if (value instanceof List<?> listVal) {
                    List<Object> items = new ArrayList<>();
                    for (Object item : listVal) {
                        if (item != null) {
                            Map<String, Object> nested = sdClaimsToDisclose(item);
                            items.add(nested.isEmpty() ? true : nested);
                        } else {
                            items.add(true);
                        }
                    }
                    if (items.stream().anyMatch(it -> it != Boolean.TRUE)) {
                        result.put(name, items);
                    }
                } else {
                    Map<String, Object> nested = sdClaimsToDisclose(value);
                    if (!nested.isEmpty()) result.put(name, nested);
                }
            }
        }
        return result;
    }
}