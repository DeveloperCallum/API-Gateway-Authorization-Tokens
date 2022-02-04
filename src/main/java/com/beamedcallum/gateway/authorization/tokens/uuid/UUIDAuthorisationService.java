package com.beamedcallum.gateway.authorization.tokens.uuid;

import com.beamedcallum.gateway.tokens.TokenService;
import com.beamedcallum.gateway.tokens.TokenServiceAuth;

import java.util.HashMap;
import java.util.UUID;

public class UUIDAuthorisationService<V> extends TokenService<UUIDToken<V>, UUIDAuthorisationService<V>.UUIDRunnable> {
    private HashMap<UUID, V> userData = new HashMap<>();

    public void authoriseToken(UUIDToken<V> token){
        authoriseToken(new UUIDRunnable(token));
    }

    public V getUser(UUID token) {
        return userData.get(token);
    }

    protected class UUIDRunnable implements TokenServiceAuth {
        private final UUIDToken<V> token;

        public UUIDRunnable(UUIDToken<V> token) {
            this.token = token;
        }

        @Override
        public void authoriseToken() {
            if (token.isExpired()) {
                return;
            }

            userData.put(token.getToken(), token.getReference());
        }

        @Override
        public void invalidateToken() {

        }
    }
}
