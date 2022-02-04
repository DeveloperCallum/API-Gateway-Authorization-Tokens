package com.beamedcallum.gateway.authorization.tokens.jwt.encoding;

import com.beamedcallum.gateway.authorization.tokens.jwt.encoding.JWTEncodingProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class JWTHmacEncoder implements JWTEncodingProvider {
    private String key;

    public JWTHmacEncoder() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`~1!2@3#4$5%6^7&8*9(0)-_=+[{]}\\|;:‘”\",<.>/?";
        StringBuilder stringBuilder = new StringBuilder();

        for (int x = 0; x <= 43; x++){
            SecureRandom secureRandom = new SecureRandom();
            stringBuilder.append(characters.charAt(secureRandom.nextInt(characters.length())));
        }

        key = stringBuilder.toString();
    }

    public JWTHmacEncoder(String key) {
        this.key = key;
    }

    @Override
    public String encodeBase64(String data) {
        Mac sha256_HMAC;
        byte[] result;

        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
            sha256_HMAC.init(secret_key);

            result = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
    }
}
