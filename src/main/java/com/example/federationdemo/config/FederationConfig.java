package com.example.federationdemo.config;

import com.example.federationdemo.service.EntityStore;
import com.example.federationdemo.service.StatementBuilder;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class FederationConfig {

    private static final Logger log = LoggerFactory.getLogger(FederationConfig.class);

    @Value("${federation.base-url}")
    private String baseUrl;

    // ── Sleutels: laden uit env var indien aanwezig, anders nieuw genereren ───

    @Bean public ECKey anchorKey()              throws Exception { return loadOrGenerate("ANCHOR_JWK",           "anchor-key-1"); }
    @Bean public ECKey intermediateKey()        throws Exception { return loadOrGenerate("INTERMEDIATE_JWK",     "intermediate-key-1"); }
    @Bean public ECKey leafKey()                throws Exception { return loadOrGenerate("LEAF_JWK",             "leaf-key-1"); }
    @Bean public ECKey intermediate2Key()       throws Exception { return loadOrGenerate("INTERMEDIATE2_JWK",    "intermediate2-key-1"); }
    @Bean public ECKey leaf2Key()               throws Exception { return loadOrGenerate("LEAF2_JWK",            "leaf2-key-1"); }
    @Bean public ECKey rogueKey()               throws Exception { return loadOrGenerate("ROGUE_JWK",            "rogue-key-1"); }
    @Bean public ECKey leafExpiredKey()         throws Exception { return loadOrGenerate("LEAF_EXPIRED_JWK",     "leaf-expired-key-1"); }
    @Bean public ECKey leafWrongSigningKey()    throws Exception { return loadOrGenerate("LEAF_WRONGKEY_SIGN_JWK",  "leaf-wrongkey-actual-1"); }
    @Bean public ECKey leafWrongRegisteredKey() throws Exception { return loadOrGenerate("LEAF_WRONGKEY_REG_JWK",   "leaf-wrongkey-registered-1"); }

    private ECKey loadOrGenerate(String envVar, String keyId) throws Exception {
        String jwkJson = System.getenv(envVar);
        if (jwkJson != null && !jwkJson.isBlank()) {
            log.info("Sleutel '{}' geladen uit env var {}", keyId, envVar);
            return ECKey.parse(jwkJson);
        }
        log.warn("Env var {} niet gevonden — tijdelijke sleutel gegenereerd voor '{}'", envVar, keyId);
        return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
    }

    // ── EntityStore ───────────────────────────────────────────────────────────

    @Bean
    public EntityStore entityStore(
            ECKey anchorKey, ECKey intermediateKey, ECKey leafKey,
            ECKey intermediate2Key, ECKey leaf2Key,
            ECKey rogueKey, ECKey leafExpiredKey,
            ECKey leafWrongSigningKey, ECKey leafWrongRegisteredKey,
            StatementBuilder builder) throws Exception {

        EntityStore store = new EntityStore();
        long now = Instant.now().getEpochSecond();
        long exp = now + 86400;

        // Sleutels opslaan
        Map<String, Object> anchorJwks        = buildJwks(anchorKey);
        Map<String, Object> intermediateJwks   = buildJwks(intermediateKey);
        Map<String, Object> leafJwks           = buildJwks(leafKey);
        Map<String, Object> intermediate2Jwks  = buildJwks(intermediate2Key);
        Map<String, Object> leaf2Jwks          = buildJwks(leaf2Key);
        Map<String, Object> rogueJwks          = buildJwks(rogueKey);
        Map<String, Object> leafExpiredJwks    = buildJwks(leafExpiredKey);
        Map<String, Object> leafWrongSignJwks  = buildJwks(leafWrongSigningKey);
        Map<String, Object> leafWrongRegJwks   = buildJwks(leafWrongRegisteredKey);

        store.putEcKey("anchor",                 anchorKey);
        store.putEcKey("intermediate",           intermediateKey);
        store.putEcKey("leaf",                   leafKey);
        store.putEcKey("intermediate2",          intermediate2Key);
        store.putEcKey("leaf2",                  leaf2Key);
        store.putEcKey("rogue",                  rogueKey);
        store.putEcKey("leaf-expired",           leafExpiredKey);
        store.putEcKey("leaf-wrongkey-signing",  leafWrongSigningKey);
        store.putEcKey("leaf-wrongkey-registered", leafWrongRegisteredKey);

        store.putJwks("anchor",       anchorJwks);
        store.putJwks("intermediate", intermediateJwks);
        store.putJwks("leaf",         leafJwks);
        store.putJwks("intermediate2",intermediate2Jwks);
        store.putJwks("leaf2",        leaf2Jwks);
        store.putJwks("rogue",        rogueJwks);
        store.putJwks("leaf-expired", leafExpiredJwks);
        store.putJwks("leaf-wrongkey",leafWrongSignJwks);

        // ── Anchor ────────────────────────────────────────────────────────────
        store.putEntityConfig("anchor", builder.sign(Map.of(
                "iss", baseUrl + "/anchor",
                "sub", baseUrl + "/anchor",
                "iat", now, "exp", exp,
                "jwks", anchorJwks,
                "metadata", Map.of("federation_entity", Map.of(
                        "federation_fetch_endpoint", baseUrl + "/anchor/fetch",
                        "display_name", "Nederlandse Overheid (demo)"))),
                anchorKey));

        // ── Intermediate ──────────────────────────────────────────────────────
        store.putEntityConfig("intermediate", builder.sign(linkedMap(
                "iss", baseUrl + "/intermediate",
                "sub", baseUrl + "/intermediate",
                "iat", now, "exp", exp,
                "jwks", intermediateJwks,
                "authority_hints", List.of(baseUrl + "/anchor"),
                "metadata", Map.of("federation_entity", Map.of(
                        "federation_fetch_endpoint", baseUrl + "/intermediate/fetch",
                        "display_name", "Surf (demo)"))),
                intermediateKey));

        // ── Leaf ──────────────────────────────────────────────────────────────
        store.putEntityConfig("leaf", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf",
                "sub", baseUrl + "/leaf",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Hogeschool Utrecht (demo)"),
                        "openid_credential_issuer", Map.of(
                                "credential_issuer", baseUrl + "/leaf",
                                "token_endpoint_auth_method", "private_key_jwt"),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        // ── Anchor → Intermediate ─────────────────────────────────────────────
        store.putSubordinateStatement(baseUrl + "/anchor", baseUrl + "/intermediate",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/anchor",
                        "sub", baseUrl + "/intermediate",
                        "iat", now, "exp", exp,
                        "jwks", intermediateJwks,
                        "metadata", Map.of("federation_entity", Map.of())),
                        anchorKey));

        // ── Intermediate → Leaf ───────────────────────────────────────────────
        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leafJwks))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 2: Tweede trust pad — Intermediate2 + Leaf2
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("intermediate2", builder.sign(linkedMap(
                "iss", baseUrl + "/intermediate2",
                "sub", baseUrl + "/intermediate2",
                "iat", now, "exp", exp,
                "jwks", intermediate2Jwks,
                "authority_hints", List.of(baseUrl + "/anchor"),
                "metadata", Map.of("federation_entity", Map.of(
                        "federation_fetch_endpoint", baseUrl + "/intermediate2/fetch",
                        "display_name", "HBO-raad (demo)"))),
                intermediate2Key));

        store.putEntityConfig("leaf2", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf2",
                "sub", baseUrl + "/leaf2",
                "iat", now, "exp", exp,
                "jwks", leaf2Jwks,
                "authority_hints", List.of(baseUrl + "/intermediate2"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Hogeschool Amsterdam (demo)"),
                        "openid_credential_issuer", Map.of(
                                "credential_issuer", baseUrl + "/leaf2",
                                "token_endpoint_auth_method", "private_key_jwt"),
                        "vc_issuer", Map.of("jwks", leaf2Jwks))),
                leaf2Key));

        store.putSubordinateStatement(baseUrl + "/anchor", baseUrl + "/intermediate2",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/anchor",
                        "sub", baseUrl + "/intermediate2",
                        "iat", now, "exp", exp,
                        "jwks", intermediate2Jwks,
                        "metadata", Map.of("federation_entity", Map.of())),
                        anchorKey));

        store.putSubordinateStatement(baseUrl + "/intermediate2", baseUrl + "/leaf2",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate2",
                        "sub", baseUrl + "/leaf2",
                        "iat", now, "exp", exp,
                        "jwks", leaf2Jwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leaf2Jwks))),
                        intermediate2Key));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 3: Rogue issuer — entity bestaat, maar geen subordinate stmt
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("rogue", builder.sign(linkedMap(
                "iss", baseUrl + "/rogue",
                "sub", baseUrl + "/rogue",
                "iat", now, "exp", exp,
                "jwks", rogueJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Onbekende Instelling (demo)"),
                        "vc_issuer", Map.of("jwks", rogueJwks))),
                rogueKey));
        // Bewust GEEN subordinate statement geregistreerd voor rogue

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 4: Verlopen subordinate statement
        // ═════════════════════════════════════════════════════════════════════

        long pastExp = now - 3600; // Verlopen 1 uur geleden

        store.putEntityConfig("leaf-expired", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-expired",
                "sub", baseUrl + "/leaf-expired",
                "iat", now, "exp", exp,
                "jwks", leafExpiredJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Verlopen Instelling (demo)"),
                        "vc_issuer", Map.of("jwks", leafExpiredJwks))),
                leafExpiredKey));

        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-expired",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-expired",
                        "iat", pastExp - 86400,
                        "exp", pastExp, // verlopen!
                        "jwks", leafExpiredJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "vc_issuer", Map.of("jwks", leafExpiredJwks))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 5: Verkeerde sleutel in subordinate statement
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-wrongkey", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-wrongkey",
                "sub", baseUrl + "/leaf-wrongkey",
                "iat", now, "exp", exp,
                "jwks", leafWrongSignJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Verkeerde Sleutel (demo)"),
                        "vc_issuer", Map.of("jwks", leafWrongSignJwks))),
                leafWrongSigningKey));

        // Intermediate registreert bewust een ANDERE public key in vc_issuer.jwks
        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-wrongkey",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-wrongkey",
                        "iat", now, "exp", exp,
                        "jwks", leafWrongSignJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leafWrongRegJwks))), // bewust verkeerde JWKS
                        intermediateKey));

        return store;
    }

    @Bean
    public FederationProperties federationProperties(ECKey anchorKey, EntityStore entityStore) {
        List<Map<String, Object>> anchorKeys =
                (List<Map<String, Object>>) entityStore.getJwks("anchor").get("keys");
        return new FederationProperties(baseUrl + "/anchor", anchorKeys);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    private Map<String, Object> buildJwks(ECKey key) throws Exception {
        ECKey pub = key.toPublicJWK();
        Map<String, Object> keyMap = new LinkedHashMap<>();
        keyMap.put("kty", "EC");
        keyMap.put("kid", pub.getKeyID());
        keyMap.put("crv", "P-256");
        keyMap.put("x", pub.getX().toString());
        keyMap.put("y", pub.getY().toString());
        return Map.of("keys", List.of(keyMap));
    }

    /** Bouwt een LinkedHashMap met afwisselend key-value paren. */
    @SuppressWarnings("unchecked")
    private <K, V> Map<K, V> linkedMap(Object... kvPairs) {
        LinkedHashMap<K, V> map = new LinkedHashMap<>();
        for (int i = 0; i < kvPairs.length; i += 2) {
            map.put((K) kvPairs[i], (V) kvPairs[i + 1]);
        }
        return map;
    }
}
