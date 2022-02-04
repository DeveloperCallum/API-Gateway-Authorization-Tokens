package com.beamedcallum.gateway.authorization.tokens.uuid;
import com.beamedcallum.gateway.tokens.ReferenceToken;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class UUIDToken<V> extends ReferenceToken<UUID, V> {
    private UUID uuid;
    private Date expiryDate;
    private V data;

    public UUIDToken(UUID uuid, V data) {
        this.uuid = uuid;
        this.data = data;
        this.expiryDate = new Date(new Date().getTime() + TimeUnit.HOURS.toMillis(30));
    }

    public UUID getToken() {
        return uuid;
    }

    @Override
    public V getReference() {
        return data;
    }

    @Override
    protected boolean checkExpired() {
        return expiryDate.before(new Date());
    }

    @Override
    public String toString() {
        return uuid.toString();
    }

    @Override
    public String get() {
        return uuid.toString();
    }
}
