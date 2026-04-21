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
    @Bean public ECKey leafMultihintKey()       throws Exception { return loadOrGenerate("LEAF_MULTIHINT_JWK",   "leaf-multihint-key-1"); }
    @Bean public ECKey leafNohintKey()          throws Exception { return loadOrGenerate("LEAF_NOHINT_JWK",      "leaf-nohint-key-1"); }
    @Bean public ECKey leafSubwrongKey()        throws Exception { return loadOrGenerate("LEAF_SUBWRONG_JWK",    "leaf-subwrong-key-1"); }

    private ECKey loadOrGenerate(String envVar, String keyId) throws Exception {
        String jwkJson = System.getenv(envVar);
        if (jwkJson != null && !jwkJson.isBlank()) {
            jwkJson = jwkJson.trim();
            // Railway slaat soms waarden op met outer quotes en ge-escapete inner quotes
            if (jwkJson.startsWith("\"") && jwkJson.endsWith("\"")) {
                jwkJson = jwkJson.substring(1, jwkJson.length() - 1).replace("\\\"", "\"");
            }
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
            ECKey leafMultihintKey, ECKey leafNohintKey, ECKey leafSubwrongKey,
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
        Map<String, Object> leafMultihintJwks  = buildJwks(leafMultihintKey);
        Map<String, Object> leafNohintJwks     = buildJwks(leafNohintKey);
        Map<String, Object> leafSubwrongJwks   = buildJwks(leafSubwrongKey);

        store.putEcKey("anchor",                 anchorKey);
        store.putEcKey("intermediate",           intermediateKey);
        store.putEcKey("leaf",                   leafKey);
        store.putEcKey("intermediate2",          intermediate2Key);
        store.putEcKey("leaf2",                  leaf2Key);
        store.putEcKey("rogue",                  rogueKey);
        store.putEcKey("leaf-expired",           leafExpiredKey);
        store.putEcKey("leaf-wrongkey-signing",  leafWrongSigningKey);
        store.putEcKey("leaf-wrongkey-registered", leafWrongRegisteredKey);
        store.putEcKey("leaf-multihint",         leafMultihintKey);
        store.putEcKey("leaf-nohint",            leafNohintKey);
        store.putEcKey("leaf-subwrong",          leafSubwrongKey);

        store.putJwks("anchor",       anchorJwks);
        store.putJwks("intermediate", intermediateJwks);
        store.putJwks("leaf",         leafJwks);
        store.putJwks("intermediate2",intermediate2Jwks);
        store.putJwks("leaf2",        leaf2Jwks);
        store.putJwks("rogue",        rogueJwks);
        store.putJwks("leaf-expired", leafExpiredJwks);
        store.putJwks("leaf-wrongkey",   leafWrongSignJwks);
        store.putJwks("leaf-multihint",  leafMultihintJwks);
        store.putJwks("leaf-nohint",     leafNohintJwks);
        store.putJwks("leaf-subwrong",   leafSubwrongJwks);

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

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 9: Twee authority hints — één geldig, één verwijst nergens
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-multihint", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-multihint",
                "sub", baseUrl + "/leaf-multihint",
                "iat", now, "exp", exp,
                "jwks", leafMultihintJwks,
                "authority_hints", List.of(
                        baseUrl + "/nonexistent-intermediate", // bestaat niet
                        baseUrl + "/intermediate"),            // geldig
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Hogeschool Veelpad (demo)"),
                        "vc_issuer", Map.of("jwks", leafMultihintJwks))),
                leafMultihintKey));

        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-multihint",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-multihint",
                        "iat", now, "exp", exp,
                        "jwks", leafMultihintJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "vc_issuer", Map.of("jwks", leafMultihintJwks))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 10: Twee authority hints — beide ongeldig
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-nohint", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-nohint",
                "sub", baseUrl + "/leaf-nohint",
                "iat", now, "exp", exp,
                "jwks", leafNohintJwks,
                "authority_hints", List.of(
                        baseUrl + "/nonexistent-1",
                        baseUrl + "/nonexistent-2"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Hogeschool Geenpad (demo)"),
                        "vc_issuer", Map.of("jwks", leafNohintJwks))),
                leafNohintKey));
        // Bewust GEEN subordinate statement — chain resolution heeft nergens te halen

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 12: Subordinate statement sub matcht niet met leaf entity-id
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-subwrong", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-subwrong",
                "sub", baseUrl + "/leaf-subwrong",
                "iat", now, "exp", exp,
                "jwks", leafSubwrongJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Verkeerde Sub (demo)"),
                        "vc_issuer", Map.of("jwks", leafSubwrongJwks))),
                leafSubwrongKey));

        // Intermediate geeft een subordinate statement uit met bewust verkeerde sub-claim
        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-subwrong",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-subwrong-WRONG", // bewust afwijkend
                        "iat", now, "exp", exp,
                        "jwks", leafSubwrongJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "vc_issuer", Map.of("jwks", leafSubwrongJwks))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 6: metadata_policy beperkt toegestane credential types
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-policy-type", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-policy-type",
                "sub", baseUrl + "/leaf-policy-type",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Policy Type Leaf (demo)"),
                        "openid_credential_issuer", Map.of(
                                "credential_issuer", baseUrl + "/leaf-policy-type",
                                "credential_types_supported", List.of("DiplomaCertificate")),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-policy-type",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-policy-type",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leafJwks)),
                        "metadata_policy", Map.of(
                                "openid_credential_issuer", Map.of(
                                        "credential_types_supported", Map.of(
                                                "subset_of", List.of("StudentCardCredential"))))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 7: metadata_policy overschrijft vc_issuer.jwks
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-policy-jwks", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-policy-jwks",
                "sub", baseUrl + "/leaf-policy-jwks",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Policy JWKS Leaf (demo)"),
                        "openid_credential_issuer", Map.of(
                                "credential_issuer", baseUrl + "/leaf-policy-jwks",
                                "credential_types_supported", List.of("DiplomaCertificate")),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-policy-jwks",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-policy-jwks",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leafJwks)),
                        "metadata_policy", Map.of(
                                "vc_issuer", Map.of(
                                        "jwks", Map.of("value", leafWrongRegJwks)))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 8: metadata_policy_crit bevat onbekende operator
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-policy-crit", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-policy-crit",
                "sub", baseUrl + "/leaf-policy-crit",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/intermediate"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Policy Crit Leaf (demo)"),
                        "openid_credential_issuer", Map.of(
                                "credential_issuer", baseUrl + "/leaf-policy-crit",
                                "credential_types_supported", List.of("DiplomaCertificate")),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        store.putSubordinateStatement(baseUrl + "/intermediate", baseUrl + "/leaf-policy-crit",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate",
                        "sub", baseUrl + "/leaf-policy-crit",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of(
                                "federation_entity", Map.of(),
                                "openid_credential_issuer", Map.of(),
                                "vc_issuer", Map.of("jwks", leafJwks)),
                        "metadata_policy_crit", List.of("unknown_operator"),
                        "metadata_policy", Map.of(
                                "openid_credential_issuer", Map.of(
                                        "credential_types_supported", Map.of(
                                                "unknown_operator", List.of("DiplomaCertificate"))))),
                        intermediateKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 13: chain dieper dan MAX_HOPS
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("leaf-deep", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-deep",
                "sub", baseUrl + "/leaf-deep",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/inter-depth-1"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Te Diepe Leaf (demo)"),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        for (int i = 1; i <= 6; i++) {
            String entity = "inter-depth-" + i;
            String parent = i == 6 ? baseUrl + "/anchor" : baseUrl + "/inter-depth-" + (i + 1);
            store.putEntityConfig(entity, builder.sign(linkedMap(
                    "iss", baseUrl + "/" + entity,
                    "sub", baseUrl + "/" + entity,
                    "iat", now, "exp", exp,
                    "jwks", intermediateJwks,
                    "authority_hints", List.of(parent),
                    "metadata", Map.of("federation_entity", Map.of(
                            "federation_fetch_endpoint", baseUrl + "/" + entity + "/fetch",
                            "display_name", "Depth Intermediate " + i))),
                    intermediateKey));
        }

        store.putSubordinateStatement(baseUrl + "/inter-depth-1", baseUrl + "/leaf-deep",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/inter-depth-1",
                        "sub", baseUrl + "/leaf-deep",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of("federation_entity", Map.of(), "vc_issuer", Map.of("jwks", leafJwks))),
                        intermediateKey));
        for (int i = 2; i <= 6; i++) {
            String issuer = baseUrl + "/inter-depth-" + i;
            String subject = baseUrl + "/inter-depth-" + (i - 1);
            store.putSubordinateStatement(issuer, subject,
                    builder.sign(linkedMap(
                            "iss", issuer,
                            "sub", subject,
                            "iat", now, "exp", exp,
                            "jwks", intermediateJwks,
                            "metadata", Map.of("federation_entity", Map.of())),
                            intermediateKey));
        }
        store.putSubordinateStatement(baseUrl + "/anchor", baseUrl + "/inter-depth-6",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/anchor",
                        "sub", baseUrl + "/inter-depth-6",
                        "iat", now, "exp", exp,
                        "jwks", intermediateJwks,
                        "metadata", Map.of("federation_entity", Map.of())),
                        anchorKey));

        // ═════════════════════════════════════════════════════════════════════
        // Scenario 14: max_path_length: 0 laat geen intermediate toe
        // ═════════════════════════════════════════════════════════════════════

        store.putEntityConfig("intermediate-maxpath", builder.sign(linkedMap(
                "iss", baseUrl + "/intermediate-maxpath",
                "sub", baseUrl + "/intermediate-maxpath",
                "iat", now, "exp", exp,
                "jwks", intermediateJwks,
                "authority_hints", List.of(baseUrl + "/anchor"),
                "metadata", Map.of("federation_entity", Map.of(
                        "federation_fetch_endpoint", baseUrl + "/intermediate-maxpath/fetch",
                        "display_name", "Max Path Intermediate (demo)"))),
                intermediateKey));

        store.putEntityConfig("leaf-maxpath", builder.sign(linkedMap(
                "iss", baseUrl + "/leaf-maxpath",
                "sub", baseUrl + "/leaf-maxpath",
                "iat", now, "exp", exp,
                "jwks", leafJwks,
                "authority_hints", List.of(baseUrl + "/intermediate-maxpath"),
                "metadata", Map.of(
                        "federation_entity", Map.of("display_name", "Max Path Leaf (demo)"),
                        "vc_issuer", Map.of("jwks", leafJwks))),
                leafKey));

        store.putSubordinateStatement(baseUrl + "/intermediate-maxpath", baseUrl + "/leaf-maxpath",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/intermediate-maxpath",
                        "sub", baseUrl + "/leaf-maxpath",
                        "iat", now, "exp", exp,
                        "jwks", leafJwks,
                        "metadata", Map.of("federation_entity", Map.of(), "vc_issuer", Map.of("jwks", leafJwks))),
                        intermediateKey));

        store.putSubordinateStatement(baseUrl + "/anchor", baseUrl + "/intermediate-maxpath",
                builder.sign(linkedMap(
                        "iss", baseUrl + "/anchor",
                        "sub", baseUrl + "/intermediate-maxpath",
                        "iat", now, "exp", exp,
                        "jwks", intermediateJwks,
                        "metadata", Map.of("federation_entity", Map.of()),
                        "constraints", Map.of("max_path_length", 0)),
                        anchorKey));

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
