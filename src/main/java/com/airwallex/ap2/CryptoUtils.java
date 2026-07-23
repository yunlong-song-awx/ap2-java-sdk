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

import com.airwallex.ap2.protocol.JsonWebKey;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

public final class CryptoUtils {
    private CryptoUtils() {
    }

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    public static String b64urlEncode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    public static byte[] b64urlDecode(String s) {
        return DECODER.decode(s);
    }

    public static String computeSha256B64url(String data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return b64urlEncode(digest);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static JsonWebKey ecKeyToJwk(ECPublicKey publicKey) {
        var w = publicKey.getW();
        int fieldSize = (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        byte[] x = padStart(w.getAffineX().toByteArray(), fieldSize);
        byte[] y = padStart(w.getAffineY().toByteArray(), fieldSize);
        return new JsonWebKey(
                "EC", "P-256", b64urlEncode(x), b64urlEncode(y),
                null, null, "ES256", null, null, null, null, null);
    }

    private static byte[] padStart(byte[] bytes, int size) {
        if (bytes.length == size) return bytes;
        if (bytes.length > size) return java.util.Arrays.copyOfRange(bytes, bytes.length - size, bytes.length);
        byte[] result = new byte[size];
        System.arraycopy(bytes, 0, result, size - bytes.length, bytes.length);
        return result;
    }
}