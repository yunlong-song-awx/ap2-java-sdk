package com.airwallex.ap2.sdjwt;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SdJwtVerifierTest {
    private final ECKey ecKey;

    SdJwtVerifierTest() throws Exception {
        this.ecKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    private ECPrivateKey privateKey() {
        try {
            return ecKey.toECPrivateKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ECPublicKey publicKey() {
        try {
            return ecKey.toECPublicKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void verifiesAndResolvesPlainClaims() {
        Map<Object, Object> claims = Map.of("sub", "user-1", "name", "Alice");
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> publicKey(), null, null);
        assertThat(verifier.getVerifiedPayload().get("sub")).isEqualTo("user-1");
        assertThat(verifier.getVerifiedPayload().get("name")).isEqualTo("Alice");
    }

    @Test
    void verifiesAndResolvesPropertyDisclosures() {
        Map<Object, Object> claims = Map.of(new SdObject<>("secret"), "hidden", "public", "visible");
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> publicKey(), null, null);
        Map<String, Object> payload = verifier.getVerifiedPayload();
        assertThat(payload.get("secret")).isEqualTo("hidden");
        assertThat(payload.get("public")).isEqualTo("visible");
    }

    @Test
    void verifiesAndResolvesArrayElementDisclosures() {
        Map<Object, Object> claims = Map.of("items", List.of(new SdObject<>("a"), "b", new SdObject<>("c")));
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> publicKey(), null, null);
        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) verifier.getVerifiedPayload().get("items");
        assertThat(items).containsExactly("a", "b", "c");
    }

    @Test
    void unrevealedArrayElementsAreExcluded() {
        Map<Object, Object> claims = Map.of("items", List.of(new SdObject<>("a"), new SdObject<>("b")));
        String fullToken = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtHolder holder = new SdJwtHolder(fullToken);
        holder.createPresentation(Map.of());
        SdJwtVerifier verifier = new SdJwtVerifier(holder.getSdJwtPresentation(), (issuer, header) -> publicKey(),
                null, null);
        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) verifier.getVerifiedPayload().get("items");
        assertThat(items).isEmpty();
    }

    @Test
    void failsWithWrongPublicKey() throws Exception {
        ECPublicKey otherKey = new ECKeyGenerator(Curve.P_256).generate().toECPublicKey();
        Map<Object, Object> claims = Map.of("sub", "test");
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> otherKey, null, null);
        assertThatThrownBy(verifier::getVerifiedPayload)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("SD-JWT verification failed")
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validatesExpectedAud() {
        Map<Object, Object> claims = Map.of("sub", "test", "aud", "correct-aud");
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier1 = new SdJwtVerifier(token, (issuer, header) -> publicKey(), "correct-aud", null);
        assertThat(verifier1.getVerifiedPayload().get("aud")).isEqualTo("correct-aud");
        SdJwtVerifier verifier2 = new SdJwtVerifier(token, (issuer, header) -> publicKey(), "wrong-aud", null);
        assertThatThrownBy(verifier2::getVerifiedPayload)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("SD-JWT verification failed")
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validatesExpectedNonce() {
        Map<Object, Object> claims = Map.of("sub", "test", "nonce", "n-1");
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> publicKey(), null, "wrong");
        assertThatThrownBy(verifier::getVerifiedPayload)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("SD-JWT verification failed")
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolvesNestedPropertyDisclosures() {
        Map<Object, Object> claims = Map.of("outer",
                Map.of(new SdObject<>("nested_secret"), "deep-hidden", "nested_public", "deep-visible"));
        String token = new SdJwtIssuer(claims, privateKey(), null, false, Map.of()).getSdJwtIssuance();
        SdJwtVerifier verifier = new SdJwtVerifier(token, (issuer, header) -> publicKey(), null, null);
        @SuppressWarnings("unchecked")
        Map<String, Object> outer = (Map<String, Object>) verifier.getVerifiedPayload().get("outer");
        assertThat(outer.get("nested_secret")).isEqualTo("deep-hidden");
        assertThat(outer.get("nested_public")).isEqualTo("deep-visible");
    }
}