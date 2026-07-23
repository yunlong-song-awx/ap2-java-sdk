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

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CryptoUtilsTest {
    @Test
    void b64urlEncode_and_b64urlDecode_roundTrip() {
        byte[] original = "hello world".getBytes(StandardCharsets.UTF_8);
        String encoded = CryptoUtils.b64urlEncode(original);
        assertThat(encoded).doesNotContain("=", "+", "/");
        assertThat(CryptoUtils.b64urlDecode(encoded)).isEqualTo(original);
    }

    @Test
    void b64urlEncode_produces_no_padding() {
        String encoded = CryptoUtils.b64urlEncode(new byte[] {0x01});
        assertThat(encoded).doesNotEndWith("=");
    }

    @Test
    void computeSha256B64url_produces_deterministic_base64url_hash() {
        String hash1 = CryptoUtils.computeSha256B64url("test");
        String hash2 = CryptoUtils.computeSha256B64url("test");
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).isNotBlank();
        assertThat(hash1).doesNotContain("=", "+", "/");
    }

    @Test
    void computeSha256B64url_produces_different_hashes_for_different_inputs() {
        String hash1 = CryptoUtils.computeSha256B64url("abc");
        String hash2 = CryptoUtils.computeSha256B64url("def");
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void ecKeyToJwk_converts_EC_P256_key_to_JWK() throws Exception {
        var ecKey = new ECKeyGenerator(Curve.P_256).generate();
        var publicKey = ecKey.toECPublicKey();

        var jwk = CryptoUtils.ecKeyToJwk(publicKey);
        assertThat(jwk.kty()).isEqualTo("EC");
        assertThat(jwk.crv()).isEqualTo("P-256");
        assertThat(jwk.alg()).isEqualTo("ES256");
        assertThat(jwk.x()).isNotBlank();
        assertThat(jwk.y()).isNotBlank();
        assertThat(jwk.x()).hasSize(43);
        assertThat(jwk.y()).hasSize(43);
    }
}