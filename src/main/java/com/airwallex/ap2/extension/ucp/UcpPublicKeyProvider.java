package com.airwallex.ap2.extension.ucp;

import com.airwallex.ap2.sdjwt.SdJwtChain;
import com.airwallex.ap2.sdjwt.SdJwtCommon;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UcpPublicKeyProvider implements SdJwtChain.PublicKeyProvider {

    private static final Logger logger = LoggerFactory.getLogger(UcpPublicKeyProvider.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final HttpClient httpClient;

    public UcpPublicKeyProvider() {
        this(HttpClient.newHttpClient());
    }

    public UcpPublicKeyProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public ECPublicKey resolve(SdJwtCommon.ParsedToken token) {
        Map<String, Object> header = token.getHeader();
        String iss = (String) header.get("iss");
        String kid = (String) header.get("kid");
        return fetchPublicKey(iss, kid);
    }

    private ECPublicKey fetchPublicKey(String iss, String kid) {
        if (!iss.endsWith("/.well-known/ucp")) {
            logger.warn("iss claim '{}' does not end with /.well-known/ucp, appending suffix", iss);
            iss = iss + "/.well-known/ucp";
        }
        String jwksUrl = iss;
        logger.debug("Fetching JWKS from {}", jwksUrl);

        String jwksJson;
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(jwksUrl))
                    .GET()
                    .build();
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException(
                        "Failed to fetch JWKS from " + jwksUrl + ": HTTP " + response.statusCode());
            }
            jwksJson = response.body();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch JWKS from " + jwksUrl + ": " + e.getMessage(), e);
        }

        UcpDiscoveryProfile profile;
        try {
            profile = mapper.readValue(jwksJson, UcpDiscoveryProfile.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JWKS response from " + jwksUrl + ": " + e.getMessage(), e);
        }

        if (profile.signingKeys() == null || profile.signingKeys().isEmpty()) {
            throw new RuntimeException("No 'signing_keys' field in JWKS response from " + jwksUrl);
        }

        ECKey jwkKey = profile.signingKeys().stream()
                .filter(k -> kid == null || kid.equals(k.getKeyID()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "No key matching kid=" + kid + " in JWKS from " + jwksUrl));

        try {
            return jwkKey.toECPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build EC key from JWK for kid=" + jwkKey.getKeyID() + ": " + e.getMessage(),
                    e);
        }
    }
}