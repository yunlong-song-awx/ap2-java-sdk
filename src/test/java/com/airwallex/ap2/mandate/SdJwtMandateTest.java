package com.airwallex.ap2.mandate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.airwallex.ap2.protocol.Amount;
import com.airwallex.ap2.protocol.CheckoutMandate;
import com.airwallex.ap2.protocol.Merchant;
import com.airwallex.ap2.protocol.PaymentInstrument;
import com.airwallex.ap2.protocol.PaymentMandate;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import org.junit.jupiter.api.Test;

class SdJwtMandateTest {

    private final ECKey signingKey;
    private final ECKey wrongKey;

    {
        try {
            signingKey = new ECKeyGenerator(Curve.P_256).generate();
            wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private final MandateClient client = new MandateClient();

    @Test
    void fromSdJwtReturnsTypedMandate() throws Exception {
        var mandate = new CheckoutMandate(null, "jwt", "hash", null, null);
        var token = client.create(List.of(mandate), signingKey.toECPrivateKey());
        var result = SdJwtMandate.fromSdJwt(token, signingKey.toECPublicKey(), CheckoutMandate.class);
        assertThat(result).isNotNull();
        assertThat(result.mandatePayload()).isInstanceOf(CheckoutMandate.class);
        assertThat(result.mandatePayload().checkoutHash()).isEqualTo("hash");
        assertThat(result.serialized()).contains("~");
        assertThat(result.isValid()).isTrue();
    }

    @Test
    void fromSdJwtFailsWithWrongKey() throws Exception {
        var mandate = new CheckoutMandate(null, "jwt", "hash", null, null);
        var token = client.create(List.of(mandate), signingKey.toECPrivateKey());
        assertThatThrownBy(() -> SdJwtMandate.fromSdJwt(token, wrongKey.toECPublicKey(), CheckoutMandate.class))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void fromSdJwtRejectsMalformedToken() {
        assertThatThrownBy(() -> SdJwtMandate.fromSdJwt("not-a-valid-token", signingKey.toECPublicKey(),
                CheckoutMandate.class))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void fromSdJwtParsesPaymentMandate() throws Exception {
        var mandate = new PaymentMandate(null, "txn-1", new Merchant("m-1", "Shop", null), new Amount(1000, "USD"), new PaymentInstrument("card-1", "card", null), null, null, null, null, null);
        var token = client.create(List.of(mandate), signingKey.toECPrivateKey());
        var result = SdJwtMandate.fromSdJwt(token, signingKey.toECPublicKey(), PaymentMandate.class);
        assertThat(result.mandatePayload().transactionId()).isEqualTo("txn-1");
        assertThat(result.mandatePayload().paymentAmount().amount()).isEqualTo(1000);
    }

    @Test
    void typedVerifyReturnsMandate() throws Exception {
        var mandate = new CheckoutMandate(null, "jwt", "hash", null, null);
        var token = client.create(List.of(mandate), signingKey.toECPrivateKey());
        var result = client.verify(token, signingKey.toECPublicKey(), CheckoutMandate.class);
        assertThat(result).isInstanceOf(Mandate.class);
        assertThat(result.mandatePayload()).isInstanceOf(CheckoutMandate.class);
        assertThat(((CheckoutMandate) result.mandatePayload()).checkoutHash()).isEqualTo("hash");
    }

    @Test
    void typedVerifyRejectsChainToken() throws Exception {
        var open = new CheckoutMandate(null, "jwt", "hash", null, null);
        var rootToken = client.create(List.of(open), signingKey.toECPrivateKey());
        assertThatThrownBy(() -> client.verify(rootToken + "~~" + rootToken, signingKey.toECPublicKey(),
                CheckoutMandate.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Typed verify requires a single token");
    }

    @Test
    void presentWithConvenienceOverload() throws Exception {
        var open = new CheckoutMandate(null, "jwt", "hash", null, null);
        var closed = new CheckoutMandate(null, "jwt2", "hash2", null, null);
        var rootToken = client.create(List.of(open), signingKey.toECPrivateKey());
        var chain = client.present(signingKey.toECPrivateKey(), rootToken, List.of(closed), "n", "a");
        assertThat(chain).contains("~~");
    }
}