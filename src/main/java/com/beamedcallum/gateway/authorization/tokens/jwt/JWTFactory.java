package com.beamedcallum.gateway.authorization.tokens.jwt;

import com.beamedcallum.gateway.authorization.tokens.jwt.encoding.JWTEncodingProvider;
import com.beamedcallum.gateway.authorization.tokens.jwt.encoding.JWTHmacEncoder;
import com.beamedcallum.gateway.authorization.tokens.jwt.exceptions.JWTParseException;
import com.beamedcallum.gateway.tokens.exceptions.TokenIntegrityException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;

public class JWTFactory {
    private static JWTFactory jwtFactory = null;
    private final JWTEncodingProvider encodingProvider;

    private JWTFactory(JWTEncodingProvider encodingProvider) {
        this.encodingProvider = encodingProvider;
    }

    public JWTToken createDefault() {
        return new JWTToken(encodingProvider, 10, ChronoUnit.MINUTES);
    }

    public JWTToken createDefault(int lifetime, ChronoUnit measurement) {
        return new JWTToken(encodingProvider, lifetime, measurement);
    }

    public JWTToken parseFromString(String token) throws JWTParseException, TokenIntegrityException {
        if (!isValid(token)){
            throw new TokenIntegrityException("Token was invalid");
        }

        JWTToken jwtToken = new JWTToken(encodingProvider);
        jwtToken.token = token;

        String[] data = token.split("\\.");
        String claims = new String(Base64.getUrlDecoder().decode(data[1]));

        ObjectMapper mapper = new ObjectMapper();
        try {
            jwtToken.claims = mapper.readValue(claims, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new JWTParseException(e);
        }

        return jwtToken;
    }

    public synchronized static JWTFactory getInstance() {
        if (jwtFactory == null) {
            jwtFactory = new JWTFactory(new JWTHmacEncoder());
        }

        return jwtFactory;
    }

    public boolean isValid(String token) throws JWTParseException {
        String[] data = token.split("\\.");

        if (data.length != 3){
            throw new JWTParseException("Token form is invalid");
        }

        String currentSignature = encodingProvider.encodeBase64(data[0] + "." + data[1]);
        String actualSignature = data[2];

        if (currentSignature.equals(actualSignature)){
            return true;
        }

        return false;
    }
}
