package com.airwallex.ap2.sdjwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.CryptoUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class X5cChainTest {

    private final ECKey signingKey;

    {
        try {
            signingKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void resolvesWithKidLookup() throws Exception {
        var provider = new SdJwtChain.X5cOrKidPublicKeyProvider(kid -> {
            if ("key-1".equals(kid)) {
                try {
                    return signingKey.toECPublicKey();
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        });
        var header = Map.<String, Object>of("kid", "key-1");
        var token = newToken(header, Map.of());
        var key = provider.resolve(token);
        assertThat(key).isNotNull();
    }

    @Test
    void failsWhenKidMissing() {
        var provider = new SdJwtChain.X5cOrKidPublicKeyProvider(kid -> null);
        var token = newToken(Map.of(), Map.of());
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing or invalid 'kid' or 'x5c'");
    }

    @Test
    void failsWhenKidProviderReturnsNull() {
        var provider = new SdJwtChain.X5cOrKidPublicKeyProvider(kid -> null);
        var header = Map.<String, Object>of("kid", "unknown-key");
        var token = newToken(header, Map.of());
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Provider returned no key");
    }

    @Test
    void failsWhenX5cIsEmpty() {
        var provider = new SdJwtChain.X5cOrKidPublicKeyProvider(kid -> null);
        var header = Map.<String, Object>of("x5c", List.of());
        var token = newToken(header, Map.of());
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-empty list");
    }

    @Test
    void failsOnMalformedX5cCert() {
        var provider = new SdJwtChain.X5cOrKidPublicKeyProvider(kid -> null);
        var header = Map.<String, Object>of("x5c", List.of(CryptoUtils.b64urlEncode("not-a-cert".getBytes())));
        var token = newToken(header, Map.of());
        assertThatThrownBy(() -> provider.resolve(token))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private SdJwtCommon.ParsedToken newToken(Map<String, Object> header, Map<String, Object> payload) {
        return new SdJwtCommon.ParsedToken("hdr.payload.sig", List.of(), null, header, payload);
    }
}