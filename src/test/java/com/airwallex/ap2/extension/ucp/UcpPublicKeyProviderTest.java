package com.airwallex.ap2.extension.ucp;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.sdjwt.SdJwtCommon;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class UcpPublicKeyProviderTest {

    @Test
    void resolveFailsWhenIssMissing() {
        var provider = new UcpPublicKeyProvider();
        var token = newToken(Map.of("kid", "key-1"), Map.of());
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void resolveFailsWhenKidMissing() {
        var provider = new UcpPublicKeyProvider();
        var token = newToken(Map.of(), Map.of("iss", "https://example.com"));
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(RuntimeException.class);
    }

    private SdJwtCommon.ParsedToken newToken(Map<String, Object> header, Map<String, Object> payload) {
        return new SdJwtCommon.ParsedToken("hdr.payload.sig", List.of(), null, header, payload);
    }
}