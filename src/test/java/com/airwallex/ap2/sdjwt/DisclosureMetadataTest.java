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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DisclosureMetadataTest {

    record AnnotatedTestModel(@SelectivelyDisclosable(field = true) String secret, String open) {}
    record ArrayAnnotatedTestModel(@SelectivelyDisclosable(array = true) List<String> items) {}
    record UnannotatedTestModel(String plain) {}
    record NestedAnnotatedTestModel(AnnotatedTestModel inner) {}
    record ListWithAnnotatedItems(List<AnnotatedTestModel> items) {}
    record ModelWithNullableComplex(UnannotatedTestModel nested) {}

    record SdTestPayload(@SelectivelyDisclosable(field = true) String secret, String open) {}
    record SdArrayPayload(@SelectivelyDisclosable(array = true) List<String> items) {}

    @Nested
    class ConstructorTest {
        @Test
        void defaultConstructor() {
            DisclosureMetadata meta = new DisclosureMetadata();
            assertThat(meta.getSdKeys()).isEmpty();
            assertThat(meta.getSdArrayIndices()).isEmpty();
            assertThat(meta.isDiscloseAll()).isFalse();
            assertThat(meta.getChildren()).isEmpty();
            assertThat(meta.getArrayChildren()).isEmpty();
            assertThat(meta.getAllArrayChildren()).isNull();
        }

        @Test
        void ofSdKeys() {
            DisclosureMetadata meta = DisclosureMetadata.ofSdKeys(List.of("a"));
            assertThat(meta.getSdKeys()).containsExactly("a");
            assertThat(meta.getSdArrayIndices()).isEmpty();
            assertThat(meta.isDiscloseAll()).isFalse();
            assertThat(meta.getChildren()).isEmpty();
            assertThat(meta.getArrayChildren()).isEmpty();
            assertThat(meta.getAllArrayChildren()).isNull();
        }

        @Test
        void ofDiscloseAll() {
            DisclosureMetadata meta = DisclosureMetadata.ofDiscloseAll(true);
            assertThat(meta.getSdKeys()).isEmpty();
            assertThat(meta.getSdArrayIndices()).isEmpty();
            assertThat(meta.isDiscloseAll()).isTrue();
            assertThat(meta.getChildren()).isEmpty();
            assertThat(meta.getArrayChildren()).isEmpty();
            assertThat(meta.getAllArrayChildren()).isNull();
        }

        @Test
        void ofDiscloseAllFalse() {
            DisclosureMetadata meta = DisclosureMetadata.ofDiscloseAll(false);
            assertThat(meta.isDiscloseAll()).isFalse();
        }

        @Test
        void ofChildren() {
            DisclosureMetadata childMeta = DisclosureMetadata.ofSdKeys(List.of("x"));
            DisclosureMetadata meta = DisclosureMetadata.ofChildren(Map.of("child", childMeta));
            assertThat(meta.getChildren()).containsKey("child");
            assertThat(meta.getChildren().get("child").getSdKeys()).containsExactly("x");
        }

        @Test
        void ofAllArrayChildren() {
            DisclosureMetadata itemMeta = DisclosureMetadata.ofSdKeys(List.of("y"));
            DisclosureMetadata meta = DisclosureMetadata.ofAllArrayChildren(itemMeta);
            assertThat(meta.getAllArrayChildren()).isNotNull();
            assertThat(meta.getAllArrayChildren().getSdKeys()).containsExactly("y");
        }

        @Test
        void fullConstructorWithArrayChildren() {
            DisclosureMetadata indexMeta = DisclosureMetadata.ofSdKeys(List.of("z"));
            DisclosureMetadata meta = new DisclosureMetadata(
                    List.of(), List.of(), false, Map.of(),
                    Map.of(0, indexMeta), null);
            assertThat(meta.getArrayChildren()).containsKey(0);
            assertThat(meta.getArrayChildren().get(0).getSdKeys()).containsExactly("z");
        }

        @Test
        void fullConstructorWithSdArrayIndices() {
            DisclosureMetadata meta = new DisclosureMetadata(
                    List.of(), List.of(0, 2), false, Map.of(), Map.of(), null);
            assertThat(meta.getSdArrayIndices()).containsExactly(0, 2);
        }
    }

    @Nested
    class ApplyTest {
        @Test
        void applyToMapWithSdKey() {
            DisclosureMetadata meta = DisclosureMetadata.ofSdKeys(List.of("secret"));
            Map<String, Object> data = Map.of("secret", "value", "open", "public");

            @SuppressWarnings("unchecked")
            Map<Object, Object> result = (Map<Object, Object>) meta.apply(data);

            assertThat(result.get(new SdObject<>("secret"))).isEqualTo("value");
            assertThat(result.get("open")).isEqualTo("public");
        }

        @Test
        void applyToMapWithDiscloseAll() {
            DisclosureMetadata meta = DisclosureMetadata.ofDiscloseAll(true);
            Map<String, Object> data = Map.of("a", "1", "b", "2");

            @SuppressWarnings("unchecked")
            Map<Object, Object> result = (Map<Object, Object>) meta.apply(data);

            assertThat((Collection<Object>) (Object) result.keySet())
                    .allMatch(k -> k instanceof SdObject);
        }

        @Test
        void applyToMapWithNoSdKeys() {
            DisclosureMetadata meta = new DisclosureMetadata();
            Map<String, Object> data = Map.of("a", "1", "b", "2");

            @SuppressWarnings("unchecked")
            Map<Object, Object> result = (Map<Object, Object>) meta.apply(data);

            assertThat(result).containsKey("a");
            assertThat(result).containsKey("b");
            assertThat(result).doesNotContainKey(new SdObject<>("a"));
        }

        @Test
        void applyToListWithSdArrayIndices() {
            DisclosureMetadata meta = new DisclosureMetadata(
                    List.of(), List.of(0, 2), false, Map.of(), Map.of(), null);
            List<Object> data = List.of("a", "b", "c");

            @SuppressWarnings("unchecked")
            List<Object> result = (List<Object>) meta.apply(data);

            assertThat(result).hasSize(3);
            assertThat(result.get(0)).isInstanceOf(SdObject.class);
            assertThat(result.get(1)).isEqualTo("b");
            assertThat(result.get(2)).isInstanceOf(SdObject.class);
        }

        @Test
        void applyToListWithArrayChildren() {
            DisclosureMetadata indexMeta = DisclosureMetadata.ofSdKeys(List.of("field"));
            DisclosureMetadata meta = new DisclosureMetadata(
                    List.of(), List.of(), false, Map.of(),
                    Map.of(0, indexMeta), null);
            List<Object> data = List.of(Map.of("field", "val"), Map.of("field", "other"));

            @SuppressWarnings("unchecked")
            List<Object> result = (List<Object>) meta.apply(data);

            assertThat(result).hasSize(2);
            @SuppressWarnings("unchecked")
            Map<Object, Object> first = (Map<Object, Object>) result.get(0);
            assertThat(first.get(new SdObject<>("field"))).isEqualTo("val");
            @SuppressWarnings("unchecked")
            Map<Object, Object> second = (Map<Object, Object>) result.get(1);
            assertThat(second.get("field")).isEqualTo("other");
        }

        @Test
        void applyToListWithAllArrayChildren() {
            DisclosureMetadata itemMeta = DisclosureMetadata.ofSdKeys(List.of("field"));
            DisclosureMetadata meta = DisclosureMetadata.ofAllArrayChildren(itemMeta);
            List<Object> data = List.of(Map.of("field", "a"), Map.of("field", "b"));

            @SuppressWarnings("unchecked")
            List<Object> result = (List<Object>) meta.apply(data);

            assertThat(result).hasSize(2);
            @SuppressWarnings("unchecked")
            Map<Object, Object> first = (Map<Object, Object>) result.get(0);
            assertThat(first.get(new SdObject<>("field"))).isEqualTo("a");
            @SuppressWarnings("unchecked")
            Map<Object, Object> second = (Map<Object, Object>) result.get(1);
            assertThat(second.get(new SdObject<>("field"))).isEqualTo("b");
        }

        @Test
        void applyToListWithNoMeta() {
            DisclosureMetadata meta = new DisclosureMetadata();
            List<Object> data = List.of("a", "b");

            @SuppressWarnings("unchecked")
            List<Object> result = (List<Object>) meta.apply(data);

            assertThat(result).isEqualTo(data);
        }

        @Test
        void applyToScalar() {
            DisclosureMetadata meta = DisclosureMetadata.ofSdKeys(List.of("x"));
            Object result = meta.apply("scalar");
            assertThat(result).isEqualTo("scalar");
        }

        @Test
        void applyToNestedMap() {
            DisclosureMetadata childMeta = DisclosureMetadata.ofSdKeys(List.of("inner"));
            DisclosureMetadata meta = DisclosureMetadata.ofChildren(Map.of("nested", childMeta));
            Map<String, Object> data = Map.of("nested", Map.of("inner", "val", "pub", "visible"));

            @SuppressWarnings("unchecked")
            Map<Object, Object> result = (Map<Object, Object>) meta.apply(data);

            @SuppressWarnings("unchecked")
            Map<Object, Object> nested = (Map<Object, Object>) result.get("nested");
            assertThat(nested.get(new SdObject<>("inner"))).isEqualTo("val");
            assertThat(nested.get("pub")).isEqualTo("visible");
        }
    }

    @Nested
    class FromDictTest {
        @Test
        void fromDictEmpty() {
            DisclosureMetadata meta = DisclosureMetadata.fromDict(Map.of());
            assertThat(meta.getSdKeys()).isEmpty();
            assertThat(meta.getSdArrayIndices()).isEmpty();
            assertThat(meta.isDiscloseAll()).isFalse();
            assertThat(meta.getChildren()).isEmpty();
            assertThat(meta.getArrayChildren()).isEmpty();
            assertThat(meta.getAllArrayChildren()).isNull();
        }

        @Test
        void fromDictWithSdKeys() {
            Map<String, Object> dict = Map.of("sd_keys", List.of("a", "b"));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getSdKeys()).containsExactly("a", "b");
        }

        @Test
        void fromDictWithDiscloseAll() {
            Map<String, Object> dict = Map.of("disclose_all", true);
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.isDiscloseAll()).isTrue();
        }

        @Test
        void fromDictWithSdArrayIndices() {
            Map<String, Object> dict = Map.of("sd_array_indices", List.of(1, 3));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getSdArrayIndices()).containsExactly(1, 3);
        }

        @Test
        void fromDictWithChildren() {
            Map<String, Object> dict = Map.of("children",
                    Map.of("child", Map.of("sd_keys", List.of("x"))));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getChildren()).containsKey("child");
            assertThat(meta.getChildren().get("child").getSdKeys()).containsExactly("x");
        }

        @Test
        void fromDictWithArrayChildren() {
            Map<String, Object> dict = Map.of("array_children",
                    Map.of("0", Map.of("sd_keys", List.of("x"))));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getArrayChildren()).containsKey(0);
            assertThat(meta.getArrayChildren().get(0).getSdKeys()).containsExactly("x");
        }

        @Test
        void fromDictWithAllArrayChildren() {
            Map<String, Object> dict = Map.of("all_array_children",
                    Map.of("sd_keys", List.of("y")));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getAllArrayChildren()).isNotNull();
            assertThat(meta.getAllArrayChildren().getSdKeys()).containsExactly("y");
        }

        @Test
        void fromDictWithAllFields() {
            Map<String, Object> dict = Map.of(
                    "sd_keys", List.of("a"),
                    "sd_array_indices", List.of(0),
                    "disclose_all", true,
                    "children", Map.of("c", Map.of("sd_keys", List.of("x"))),
                    "array_children", Map.of("0", Map.of("sd_keys", List.of("z"))),
                    "all_array_children", Map.of("sd_keys", List.of("y")));
            DisclosureMetadata meta = DisclosureMetadata.fromDict(dict);
            assertThat(meta.getSdKeys()).containsExactly("a");
            assertThat(meta.getSdArrayIndices()).containsExactly(0);
            assertThat(meta.isDiscloseAll()).isTrue();
            assertThat(meta.getChildren()).containsKey("c");
            assertThat(meta.getArrayChildren()).containsKey(0);
            assertThat(meta.getAllArrayChildren()).isNotNull();
        }
    }

    @Nested
    class SdClaimsToDiscloseTest {
        @Test
        void sdClaimsToDiscloseWithFieldAnnotation() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new SdTestPayload("s", "o"));
            assertThat(result).containsEntry("secret", true);
            assertThat(result).doesNotContainKey("open");
        }

        @Test
        void sdClaimsToDiscloseWithArrayAnnotation() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new SdArrayPayload(List.of("a", "b")));
            assertThat(result).containsKey("items");
            assertThat(result.get("items")).isEqualTo(List.of(true, true));
        }

        @Test
        void sdClaimsToDiscloseWithNestedAnnotatedModel() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new NestedAnnotatedTestModel(new AnnotatedTestModel("s", "o")));
            assertThat(result).containsKey("inner");
            @SuppressWarnings("unchecked")
            Map<String, Object> inner = (Map<String, Object>) result.get("inner");
            assertThat(inner).containsEntry("secret", true);
        }

        @Test
        void sdClaimsToDiscloseWithListOfAnnotatedItems() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new ListWithAnnotatedItems(List.of(
                            new AnnotatedTestModel("s1", "o1"),
                            new AnnotatedTestModel("s2", "o2"))));
            assertThat(result).containsKey("items");
            @SuppressWarnings("unchecked")
            List<Object> items = (List<Object>) result.get("items");
            assertThat(items).hasSize(2);
            @SuppressWarnings("unchecked")
            Map<String, Object> first = (Map<String, Object>) items.get(0);
            assertThat(first).containsEntry("secret", true);
        }

        @Test
        void sdClaimsToDiscloseWithUnannotatedModel() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new UnannotatedTestModel("plain"));
            assertThat(result).isEmpty();
        }

        @Test
        void sdClaimsToDiscloseWithNullableComplex() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new ModelWithNullableComplex(new UnannotatedTestModel("v")));
            assertThat(result).doesNotContainKey("nested");
        }

        @Test
        void sdClaimsToDiscloseWithNullNested() {
            Map<String, Object> result = DisclosureMetadata.sdClaimsToDisclose(
                    new ModelWithNullableComplex(null));
            assertThat(result).isEmpty();
        }
    }
}