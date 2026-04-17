package com.example.federationdemo.service;

import com.nimbusds.jose.jwk.ECKey;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class EntityStore {

    private final Map<String, String> entityConfigs = new HashMap<>();
    private final Map<String, String> subordinateStatements = new HashMap<>();
    private final Map<String, ECKey> ecKeys = new HashMap<>();
    private final Map<String, Map<String, Object>> jwksMaps = new HashMap<>();

    public void putEntityConfig(String entity, String jwt) {
        entityConfigs.put(entity, jwt);
    }

    public String getEntityConfig(String entity) {
        return entityConfigs.get(entity);
    }

    public void putSubordinateStatement(String issuer, String subject, String jwt) {
        subordinateStatements.put(issuer + "|" + subject, jwt);
    }

    public String getSubordinateStatement(String issuer, String subject) {
        return subordinateStatements.get(issuer + "|" + subject);
    }

    public void putEcKey(String entity, ECKey key) {
        ecKeys.put(entity, key);
    }

    public ECKey getEcKey(String entity) {
        return ecKeys.get(entity);
    }

    public void putJwks(String entity, Map<String, Object> jwks) {
        jwksMaps.put(entity, jwks);
    }

    public Map<String, Object> getJwks(String entity) {
        return jwksMaps.get(entity);
    }

    public Map<String, String> getAllEntityConfigs() {
        return Map.copyOf(entityConfigs);
    }

    public Map<String, Map<String, Object>> getAllJwks() {
        return Map.copyOf(jwksMaps);
    }
}
