package com.beamedcallum.gateway.authorization.tokens.jwt;

import com.beamedcallum.gateway.authorization.tokens.jwt.encoding.JWTEncodingProvider;
import com.beamedcallum.gateway.tokens.SelfContainedToken;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class JWTToken extends SelfContainedToken<String> {
    private final JWTEncodingProvider encoder;
    protected Map<String, String> claims = new LinkedHashMap<>();
    protected String token = null;

    protected JWTToken(JWTEncodingProvider encoder, int lifetime, ChronoUnit unit){
        this.encoder = encoder;

        Instant instant = Instant.now().plus(lifetime, unit);
        long expireUnix = instant.toEpochMilli();

        claims.put("exp", String.valueOf(expireUnix));
    }

    protected JWTToken(JWTEncodingProvider encoder) {
        this.encoder = encoder;
    }

    @Deprecated
    public String getToken() {
        if (token == null){
            token = generateJsonWebToken();
        }

        return token;
    }

    @Deprecated
    @Override
    public String toString() {
        return get();
    }

    public void addClaim(String claim, String value){
        claims.put(claim, value);
    }

    public String getClaim(String claim){
        return claims.get(claim);
    }

    public void regenerate(){
        if (token != null){
            token = generateJsonWebToken();
        }
    }

    @Override
    public String get() {
        if (token == null){
            token = generateJsonWebToken();
        }

        return token;
    }

    protected String generateJsonWebToken(){
        String header = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
        StringBuilder payload = new StringBuilder("{");

        int index = 0;
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (index >= claims.size() - 1){
                payload.append("\"").append(key).append("\": \"").append(value).append("\"");

                break;
            }

            payload.append("\"").append(key).append("\": \"").append(value).append("\", ");
            index++;
        }

        payload.append("}");

        String headerBase = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String payloadBase = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));

        String signature = encoder.encodeBase64(headerBase + "." + payloadBase);

        return headerBase + "." + payloadBase + "." + signature;
    }

    @Override
    protected boolean checkExpired() {
        Long expireUnix = Long.parseLong(claims.get("exp"));
        Instant expireInstant = Instant.ofEpochMilli(expireUnix);

        return Instant.now().isAfter(expireInstant);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof JWTToken)){
            return false;
        }

        JWTToken comparator = (JWTToken) obj;

        return comparator.get().equals(this.get());
    }
}
