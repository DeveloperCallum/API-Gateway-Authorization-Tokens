package com.beamedcallum.gateway.authorization.tokens.jwt.encoding;

public interface JWTEncodingProvider {
    /**
     * Encodes the data
     * @param data The data to be encoded.
     * @return The encoded data returned as Base64.
     */
    String encodeBase64(String data);
}
