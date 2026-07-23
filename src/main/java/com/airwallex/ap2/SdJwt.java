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
import com.airwallex.ap2.sdjwt.SdJwtVerifier;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

public final class SdJwt {
    private SdJwt() {
    }

    public static SdJwtIssuer create(Object payload, ECPrivateKey issuerKey, String issuerKeyId,
            DisclosureMetadata sd, boolean addDecoyClaims, Map<String, Object> extraClaims) {
        Map<String, Object> delegateClaims = SdJwtCommon.delegateClaimsFromObject(payload);
        DisclosureMetadata resolvedSd = sd != null ? sd : null;
        Map<Object, Object> sdClaims = SdJwtCommon.selectivelyDisclosableClaims(
                delegateClaims, resolvedSd, extraClaims != null ? extraClaims : Map.of());
        return new SdJwtIssuer(sdClaims, issuerKey, issuerKeyId, addDecoyClaims,
                SdJwtCommon.headerParameters(issuerKeyId, null));
    }

    public static Map<String, Object> verify(String token, ECPublicKey issuerPublicKey,
            String expectedAud, String expectedNonce) {
        SdJwtVerifier verifier = new SdJwtVerifier(token,
                (issuer, header) -> issuerPublicKey, expectedAud, expectedNonce);
        return verifier.getVerifiedPayload();
    }

    public static Map<String, Object> verify(String token, ECPublicKey issuerPublicKey) {
        return verify(token, issuerPublicKey, null, null);
    }
}