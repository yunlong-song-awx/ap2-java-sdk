package com.airwallex.ap2.mandate;

import com.airwallex.ap2.SdJwt;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

public class SdJwtMandate<T> implements Mandate<T> {

    private static final ObjectMapper mapper = new ObjectMapper();

    private final String serialized;
    private final T mandatePayload;

    public SdJwtMandate(String serialized, T mandatePayload) {
        this.serialized = serialized;
        this.mandatePayload = mandatePayload;
    }

    @Override
    public String serialized() {
        return serialized;
    }

    @Override
    public T mandatePayload() {
        return mandatePayload;
    }

    @SuppressWarnings("unchecked")
    public static <T> SdJwtMandate<T> fromSdJwt(
            String compactSerialization,
            ECPublicKey issuerPublicKey,
            Class<T> payloadType) {
        return fromSdJwt(compactSerialization, issuerPublicKey, payloadType, null, null);
    }

    @SuppressWarnings("unchecked")
    public static <T> SdJwtMandate<T> fromSdJwt(
            String compactSerialization,
            ECPublicKey issuerPublicKey,
            Class<T> payloadType,
            String expectedAud,
            String expectedNonce) {
        Map<String, Object> verifiedPayload = SdJwt.verify(
                compactSerialization, issuerPublicKey, expectedAud, expectedNonce);

        Object delegatePayload = verifiedPayload.get("delegate_payload");
        Map<String, Object> effective;
        if (delegatePayload instanceof List<?> list) {
            List<Map<String, Object>> disclosed = list.stream()
                    .filter(item -> item instanceof Map)
                    .map(item -> (Map<String, Object>) item)
                    .toList();
            if (disclosed.size() != 1) {
                throw new IllegalArgumentException(
                        "delegate_payload has " + disclosed.size() + " disclosed items, expected exactly 1");
            }
            effective = disclosed.get(0);
        } else {
            effective = verifiedPayload;
        }

        T payload = mapper.convertValue(effective, payloadType);
        SdJwtCommon.ParsedToken parsed = SdJwtCommon.parseToken(compactSerialization);
        return new SdJwtMandate<>(parsed.getCanonical(), payload);
    }
}