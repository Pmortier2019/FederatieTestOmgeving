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

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class FederationConfig {

    @Value("${federation.base-url}")
    private String baseUrl;

    @Bean
    public ECKey anchorKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID("anchor-key-1").generate();
    }

    @Bean
    public ECKey intermediateKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID("intermediate-key-1").generate();
    }

    @Bean
    public ECKey leafKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID("leaf-key-1").generate();
    }

    @Bean
    public EntityStore entityStore(
            ECKey anchorKey,
            ECKey intermediateKey,
            ECKey leafKey,
            StatementBuilder builder) throws Exception {

        EntityStore store = new EntityStore();

        Map<String, Object> anchorJwks = buildJwks(anchorKey);
        Map<String, Object> intermediateJwks = buildJwks(intermediateKey);
        Map<String, Object> leafJwks = buildJwks(leafKey);

        store.putEcKey("anchor", anchorKey);
        store.putEcKey("intermediate", intermediateKey);
        store.putEcKey("leaf", leafKey);
        store.putJwks("anchor", anchorJwks);
        store.putJwks("intermediate", intermediateJwks);
        store.putJwks("leaf", leafJwks);

        long now = Instant.now().getEpochSecond();
        long exp = now + 86400;

        // Anchor entity config (self-signed)
        Map<String, Object> anchorClaims = new LinkedHashMap<>();
        anchorClaims.put("iss", baseUrl + "/anchor");
        anchorClaims.put("sub", baseUrl + "/anchor");
        anchorClaims.put("iat", now);
        anchorClaims.put("exp", exp);
        anchorClaims.put("jwks", anchorJwks);
        anchorClaims.put("metadata", Map.of("federation_entity", Map.of(
                "federation_fetch_endpoint", baseUrl + "/anchor/fetch",
                "display_name", "Nederlandse Overheid (demo)")));
        store.putEntityConfig("anchor", builder.sign(anchorClaims, anchorKey));

        // Intermediate entity config (self-signed)
        Map<String, Object> intermediateClaims = new LinkedHashMap<>();
        intermediateClaims.put("iss", baseUrl + "/intermediate");
        intermediateClaims.put("sub", baseUrl + "/intermediate");
        intermediateClaims.put("iat", now);
        intermediateClaims.put("exp", exp);
        intermediateClaims.put("jwks", intermediateJwks);
        intermediateClaims.put("authority_hints", List.of(baseUrl + "/anchor"));
        intermediateClaims.put("metadata", Map.of("federation_entity", Map.of(
                "federation_fetch_endpoint", baseUrl + "/intermediate/fetch",
                "display_name", "Surf (demo)")));
        store.putEntityConfig("intermediate", builder.sign(intermediateClaims, intermediateKey));

        // Leaf entity config (self-signed)
        Map<String, Object> leafClaims = new LinkedHashMap<>();
        leafClaims.put("iss", baseUrl + "/leaf");
        leafClaims.put("sub", baseUrl + "/leaf");
        leafClaims.put("iat", now);
        leafClaims.put("exp", exp);
        leafClaims.put("jwks", leafJwks);
        leafClaims.put("authority_hints", List.of(baseUrl + "/intermediate"));
        leafClaims.put("metadata", Map.of(
                "federation_entity", Map.of("display_name", "Hogeschool Utrecht (demo)"),
                "openid_credential_issuer", Map.of(
                        "credential_issuer", baseUrl + "/leaf",
                        "token_endpoint_auth_method", "private_key_jwt"),
                "vc_issuer", Map.of("jwks", leafJwks)));
        store.putEntityConfig("leaf", builder.sign(leafClaims, leafKey));

        // Anchor subordinate statement about intermediate
        Map<String, Object> anchorAboutIntermediate = new LinkedHashMap<>();
        anchorAboutIntermediate.put("iss", baseUrl + "/anchor");
        anchorAboutIntermediate.put("sub", baseUrl + "/intermediate");
        anchorAboutIntermediate.put("iat", now);
        anchorAboutIntermediate.put("exp", exp);
        anchorAboutIntermediate.put("jwks", intermediateJwks);
        anchorAboutIntermediate.put("metadata", Map.of("federation_entity", Map.of()));
        store.putSubordinateStatement(
                baseUrl + "/anchor",
                baseUrl + "/intermediate",
                builder.sign(anchorAboutIntermediate, anchorKey));

        // Intermediate subordinate statement about leaf
        Map<String, Object> intermediateAboutLeaf = new LinkedHashMap<>();
        intermediateAboutLeaf.put("iss", baseUrl + "/intermediate");
        intermediateAboutLeaf.put("sub", baseUrl + "/leaf");
        intermediateAboutLeaf.put("iat", now);
        intermediateAboutLeaf.put("exp", exp);
        intermediateAboutLeaf.put("jwks", leafJwks);
        intermediateAboutLeaf.put("metadata", Map.of(
                "federation_entity", Map.of(),
                "openid_credential_issuer", Map.of(),
                "vc_issuer", Map.of()));
        store.putSubordinateStatement(
                baseUrl + "/intermediate",
                baseUrl + "/leaf",
                builder.sign(intermediateAboutLeaf, intermediateKey));

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
}
