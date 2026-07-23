package com.airwallex.ap2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.mandate.MandateClient;
import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.airwallex.ap2.sdjwt.SdJwtChain;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MandateClientTest {
    private final ECKey issuerKey;
    private final ECKey holderKey;

    {
        try {
            issuerKey = new ECKeyGenerator(Curve.P_256).generate();
            holderKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private final MandateClient client = new MandateClient();

    private CheckoutMandate checkoutMandate() {
        return new CheckoutMandate(null, "eyJhbGciOiJFUzI1NiJ9.dGVzdA.sig",
                CryptoUtils.computeSha256B64url("test"), System.currentTimeMillis() / 1000, null);
    }

    private PaymentMandate paymentMandate() {
        return new PaymentMandate(null, "txn-123",
                new Merchant("m-1", "Shop", null),
                new Amount(1000, "USD"),
                new PaymentInstrument("card-1", "card", null),
                null, null, null,
                System.currentTimeMillis() / 1000, null, null);
    }

    @Test
    void createProducesValidSdJwtToken() throws Exception {
        String token = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), "key-1", null, null, null);
        assertThat(token).contains("~");
        assertThat(token).endsWith("~");
    }

    @Test
    void createThrowsWhenPayloadsListIsEmpty() throws Exception {
        assertThatThrownBy(() -> client.create(List.of(), issuerKey.toECPrivateKey(), null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("payloads list cannot be empty");
    }

    @Test
    void createWithHolderPublicKeyEmbedsCnf() throws Exception {
        String token = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null,
                holderKey.toECPublicKey(), null);
        Map<String, Object> verified = SdJwt.verify(token, issuerKey.toECPublicKey());
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) verified.get("cnf");
        assertThat(cnf).isNotNull();
        assertThat(cnf).containsKey("jwk");
    }

    @Test
    void verifySingleTokenSucceedsWithCorrectKey() throws Exception {
        String token = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null, null, null);
        List<Map<String, Object>> payloads = client.verify(token, issuerKey.toECPublicKey(), null, null, 300,
                System.currentTimeMillis() / 1000);
        assertThat(payloads).isNotEmpty();
        assertThat(payloads.get(0)).containsKey("checkout_jwt");
    }

    @Test
    void verifySingleTokenFailsWithWrongKeyType() throws Exception {
        String token = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null, null, null);
        assertThatThrownBy(() -> client.verify(token, "not-a-key", null, null, 300, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ECPublicKey");
    }

    @Test
    void createAndPresentBuildsDelegationChain() throws Exception {
        String rootToken = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null,
                holderKey.toECPublicKey(), null);
        String chainToken = client.present(holderKey.toECPrivateKey(), rootToken, List.of(paymentMandate()), null, null,
                null, "nonce-1", "https://verifier.example.com", "sd_hash");
        assertThat(chainToken).contains("~~");
    }

    @Test
    void presentWithClaimsToDiscloseFiltersDisclosures() throws Exception {
        String rootToken = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null,
                holderKey.toECPublicKey(), null);
        String chainToken = client.present(holderKey.toECPrivateKey(), rootToken, List.of(paymentMandate()), null, null,
                Map.of("checkout_jwt", true), "nonce-1", "https://verifier.example.com", "sd_hash");
        assertThat(chainToken).contains("~~");
    }

    @Test
    void presentThrowsWhenPayloadsListIsEmpty() throws Exception {
        assertThatThrownBy(() -> client.present(holderKey.toECPrivateKey(), "token~", List.of(), null, null, null, "n",
                "a", "sd_hash"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("payloads list cannot be empty");
    }

    @Test
    void getClosedMandateJwtExtractsLeafFromChain() {
        assertThat(client.getClosedMandateJwt("open~disc~~closed~disc~")).isEqualTo("closed");
    }

    @Test
    void getClosedMandateJwtHandlesSingleToken() {
        assertThat(client.getClosedMandateJwt("header.payload.sig~")).isEqualTo("header.payload.sig");
    }

    @Test
    void getClosedMandateJwtHandlesTokenWithoutTrailingTilde() {
        assertThat(client.getClosedMandateJwt("header.payload.sig")).isEqualTo("header.payload.sig");
    }

    @Test
    void verifyChainWithPublicKeyProvider() throws Exception {
        String rootToken = client.create(List.of(checkoutMandate()), issuerKey.toECPrivateKey(), null, null,
                holderKey.toECPublicKey(), null);
        String chainToken = client.present(holderKey.toECPrivateKey(), rootToken, List.of(paymentMandate()), null, null,
                null, "nonce-1", "https://verifier.example.com", "sd_hash");
        SdJwtChain.PublicKeyProvider provider = token -> {
            try {
                return issuerKey.toECPublicKey();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        List<Map<String, Object>> payloads = client.verify(chainToken, provider, "https://verifier.example.com",
                "nonce-1", 300, System.currentTimeMillis() / 1000);
        assertThat(payloads).hasSizeGreaterThanOrEqualTo(2);
    }
}