package com.airwallex.ap2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

public final class JwtHelper {
    private JwtHelper() {}
    private static final ObjectMapper mapper = new ObjectMapper();

    public static String createJwt(Map<String, Object> payload, ECPrivateKey privateKey) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
            JWSObject jwsObject = new JWSObject(header, new Payload(mapper.writeValueAsString(payload)));
            jwsObject.sign(new ECDSASigner(privateKey));
            return jwsObject.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    public static Map<String, Object> verifyJwt(String jwt, ECPublicKey publicKey) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);
            if (!jwsObject.verify(new ECDSAVerifier(publicKey))) {
                throw new IllegalArgumentException("JWT signature verification failed");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = mapper.readValue(jwsObject.getPayload().toString(), Map.class);
            return payload;
        } catch (Exception e) {
            throw new RuntimeException("JWT verification failed", e);
        }
    }
}