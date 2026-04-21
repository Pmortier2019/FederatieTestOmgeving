package com.example.federationdemo.validation;

import com.example.federationdemo.config.FederationProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;

@Component
public class TrustChainResolver {

    private static final int MAX_HOPS = 5;

    private final RestTemplate restTemplate;
    private final EntityStatementValidator statementValidator;
    private final JwtParser jwtParser;
    private final FederationProperties federationProperties;
    private final ConstraintsValidator constraintsValidator;
    private final PolicyEvaluator policyEvaluator;
    private final TrustMarkValidator trustMarkValidator;

    public TrustChainResolver(RestTemplate restTemplate,
                               EntityStatementValidator statementValidator,
                               JwtParser jwtParser,
                               FederationProperties federationProperties,
                               ConstraintsValidator constraintsValidator,
                               PolicyEvaluator policyEvaluator,
                               TrustMarkValidator trustMarkValidator) {
        this.restTemplate = restTemplate;
        this.statementValidator = statementValidator;
        this.jwtParser = jwtParser;
        this.federationProperties = federationProperties;
        this.constraintsValidator = constraintsValidator;
        this.policyEvaluator = policyEvaluator;
        this.trustMarkValidator = trustMarkValidator;
    }

    public TrustChain resolve(String issuerIdentifier, String trustAnchorEntityId,
                               String requiredTrustMarkId) {
        try {
            return doResolve(issuerIdentifier, trustAnchorEntityId, requiredTrustMarkId);
        } catch (Exception e) {
            List<String> embedded = CredentialTrustChainHolder.get();
            if (embedded != null) {
                try {
                    return validateEmbeddedChain(embedded, trustAnchorEntityId);
                } catch (Exception embeddedEx) {
                    throw new RuntimeException("Chain resolution failed: " + e.getMessage() +
                            "; embedded chain also failed: " + embeddedEx.getMessage(), e);
                }
            }
            throw e instanceof RuntimeException re ? re : new RuntimeException(e.getMessage(), e);
        }
    }

    private TrustChain doResolve(String issuerIdentifier, String trustAnchorEntityId,
                                  String requiredTrustMarkId) {
        // Step 1-4: Fetch and validate leaf entity config
        String leafConfigJwt = fetchEntityConfig(issuerIdentifier);
        ParsedJwt leafConfig = jwtParser.parse(leafConfigJwt);
        validateSelfIssuedConfig(leafConfig, issuerIdentifier);
        PublicKey leafPublicKey = extractPublicKey(leafConfig.jwks(), leafConfigJwt);
        statementValidator.validate(leafConfig, leafPublicKey);

        List<String> statementList = new ArrayList<>();
        statementList.add(leafConfigJwt);

        TrustChain chain = resolveFromConfig(leafConfig, issuerIdentifier, trustAnchorEntityId,
                statementList, new ArrayList<>(), 0, leafConfig.metadata());

        // Step 14: Trust mark validation
        if (requiredTrustMarkId != null) {
            ParsedJwt leaf = jwtParser.parse(chain.statements().get(0));
            ParsedJwt anchor = jwtParser.parse(chain.statements().get(chain.statements().size() - 1));
            PublicKey anchorKey = extractKeyFromList(federationProperties.getTrustAnchorJwks(), anchor.rawJwt());
            trustMarkValidator.validateEntityHasTrustMark(leaf, requiredTrustMarkId, anchorKey);
        }

        return chain;
    }

    private TrustChain resolveFromConfig(ParsedJwt currentConfig,
                                         String currentId,
                                         String trustAnchorEntityId,
                                         List<String> baseStatements,
                                         List<String> subordinateJwts,
                                         int hops,
                                         Map<String, Object> leafMetadata) {
        if (hops >= MAX_HOPS) {
            throw new IllegalStateException("Maximum trust chain depth (" + MAX_HOPS + ") exceeded");
        }

        List<String> hints = currentConfig.authorityHints();
        if (hints == null || hints.isEmpty()) {
            throw new IllegalStateException("Entity '" + currentId +
                    "' has no authority_hints; cannot reach trust anchor");
        }

        List<String> failures = new ArrayList<>();
        for (String parentId : hints) {
            try {
                String parentConfigJwt = fetchEntityConfig(parentId);
                ParsedJwt parentConfig = jwtParser.parse(parentConfigJwt);
                validateSelfIssuedConfig(parentConfig, parentId);
                PublicKey parentPublicKey = extractPublicKey(parentConfig.jwks(), parentConfigJwt);
                statementValidator.validate(parentConfig, parentPublicKey);

                String subStatementJwt = fetchSubordinateStatement(parentId, currentId);
                ParsedJwt subStatement = jwtParser.parse(subStatementJwt);
                statementValidator.validate(subStatement);
                statementValidator.validate(subStatement, parentPublicKey);
                validateSubordinateStatement(subStatement, parentId, currentId);

                if (subStatement.constraints() != null) {
                    constraintsValidator.validate(subStatement.constraints(), hops, leafMetadata);
                }

                List<String> nextSubordinates = new ArrayList<>(subordinateJwts);
                nextSubordinates.add(0, subStatementJwt);

                if (parentId.equals(trustAnchorEntityId)) {
                    List<Map<String, Object>> anchorJwksList = federationProperties.getTrustAnchorJwks();
                    if (anchorJwksList == null || anchorJwksList.isEmpty()) {
                        throw new IllegalStateException("Trust anchor JWKS not configured");
                    }
                    PublicKey anchorConfiguredKey = extractKeyFromList(anchorJwksList, parentConfigJwt);
                    statementValidator.validate(parentConfig, anchorConfiguredKey);

                    List<String> statements = new ArrayList<>(baseStatements);
                    statements.addAll(nextSubordinates);
                    statements.add(parentConfigJwt);
                    TrustChain partialChain = new TrustChain(statements, null);
                    Map<String, Object> resolvedMetadata = policyEvaluator.evaluateChain(partialChain);
                    return new TrustChain(statements, resolvedMetadata);
                }

                return resolveFromConfig(parentConfig, parentId, trustAnchorEntityId,
                        baseStatements, nextSubordinates, hops + 1, leafMetadata);
            } catch (Exception ex) {
                failures.add(parentId + ": " + ex.getMessage());
            }
        }
        throw new IllegalStateException("No authority_hint led to trust anchor '" +
                trustAnchorEntityId + "'. Failures: " + failures);
    }

    public void verifyCredentialSigningKey(TrustChain chain, String kid) {
        if (chain.resolvedMetadata() == null) {
            throw new IllegalArgumentException("Chain has no resolved metadata");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> vcIssuer =
                (Map<String, Object>) chain.resolvedMetadata().get("vc_issuer");
        if (vcIssuer == null) {
            throw new IllegalArgumentException("No vc_issuer in resolved metadata");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) vcIssuer.get("jwks");
        if (jwks == null) {
            throw new IllegalArgumentException("No jwks in vc_issuer metadata");
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        if (keys == null) {
            throw new IllegalArgumentException("No keys in vc_issuer jwks");
        }
        boolean found = keys.stream().anyMatch(k -> kid.equals(k.get("kid")));
        if (!found) {
            throw new IllegalArgumentException("No key with kid '" + kid + "' found in vc_issuer jwks");
        }
    }

    private TrustChain validateEmbeddedChain(List<String> embedded, String trustAnchorEntityId) {
        if (embedded.size() < 2) {
            throw new IllegalArgumentException("Embedded chain too short");
        }

        // Format: [leafConfig, subordinate1, ..., anchorConfig]
        String leafConfigJwt = embedded.get(0);
        String anchorConfigJwt = embedded.get(embedded.size() - 1);

        ParsedJwt leafConfig = jwtParser.parse(leafConfigJwt);
        statementValidator.validate(leafConfig);
        validateSelfIssuedConfig(leafConfig, leafConfig.iss());
        PublicKey leafKey = extractPublicKey(leafConfig.jwks(), leafConfigJwt);
        statementValidator.validate(leafConfig, leafKey);

        ParsedJwt anchorConfig = jwtParser.parse(anchorConfigJwt);
        statementValidator.validate(anchorConfig);

        if (!trustAnchorEntityId.equals(anchorConfig.iss())) {
            throw new IllegalArgumentException("Embedded chain anchor does not match trust anchor");
        }

        List<Map<String, Object>> anchorJwksList = federationProperties.getTrustAnchorJwks();
        if (anchorJwksList == null || anchorJwksList.isEmpty()) {
            throw new IllegalStateException("Trust anchor JWKS not configured");
        }
        PublicKey anchorKey = extractKeyFromList(anchorJwksList, anchorConfigJwt);
        statementValidator.validate(anchorConfig, anchorKey);

        TrustChain partialChain = new TrustChain(embedded, null);
        Map<String, Object> resolvedMetadata = policyEvaluator.evaluateChain(partialChain);
        return new TrustChain(embedded, resolvedMetadata);
    }

    private void validateSelfIssuedConfig(ParsedJwt config, String expectedEntityId) {
        statementValidator.validate(config);
        if (!Objects.equals(config.iss(), expectedEntityId) || !Objects.equals(config.sub(), expectedEntityId)) {
            throw new IllegalArgumentException("Entity configuration iss/sub must both equal " + expectedEntityId);
        }
    }

    private void validateSubordinateStatement(ParsedJwt statement, String expectedIssuer, String expectedSubject) {
        if (!Objects.equals(statement.iss(), expectedIssuer)) {
            throw new IllegalArgumentException("Subordinate statement iss does not match parent: " + statement.iss());
        }
        if (!Objects.equals(statement.sub(), expectedSubject)) {
            throw new IllegalArgumentException("Subordinate statement sub does not match subject: " + statement.sub());
        }
    }

    private String fetchEntityConfig(String entityId) {
        String url = entityId + "/.well-known/openid-federation";
        String jwt = restTemplate.getForObject(url, String.class);
        if (jwt == null || jwt.isBlank()) {
            throw new IllegalStateException("Empty response from " + url);
        }
        return jwt.trim();
    }

    private String fetchSubordinateStatement(String parentId, String subjectId) {
        String encodedSub = URLEncoder.encode(subjectId, StandardCharsets.UTF_8);
        String url = parentId + "/fetch?sub=" + encodedSub;
        String jwt = restTemplate.getForObject(url, String.class);
        if (jwt == null || jwt.isBlank()) {
            throw new IllegalStateException("Empty subordinate statement from " + url);
        }
        return jwt.trim();
    }

    private PublicKey extractPublicKey(Map<String, Object> jwks, String rawJwt) {
        String kid = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(rawJwt);
            kid = signedJWT.getHeader().getKeyID();
        } catch (Exception ignored) {}

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        return findKeyInList(keys, kid);
    }

    private PublicKey extractKeyFromList(List<Map<String, Object>> keys, String rawJwt) {
        String kid = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(rawJwt);
            kid = signedJWT.getHeader().getKeyID();
        } catch (Exception ignored) {}
        return findKeyInList(keys, kid);
    }

    private PublicKey findKeyInList(List<Map<String, Object>> keys, String kid) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("JWKS contains no keys");
        }
        for (Map<String, Object> keyMap : keys) {
            if (kid == null || kid.equals(keyMap.get("kid"))) {
                try {
                    JWK jwk = JWK.parse(keyMap);
                    return jwk.toECKey().toPublicKey();
                } catch (Exception e) {
                    throw new IllegalArgumentException("Failed to parse JWK: " + e.getMessage(), e);
                }
            }
        }
        throw new IllegalArgumentException("No key found for kid: " + kid + " in JWKS");
    }
}
