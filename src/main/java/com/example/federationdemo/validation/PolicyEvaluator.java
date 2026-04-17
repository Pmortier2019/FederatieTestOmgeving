package com.example.federationdemo.validation;

import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class PolicyEvaluator {

    private static final Set<String> KNOWN_OPERATORS = Set.of(
            "value", "add", "default", "one_of", "subset_of", "superset_of", "essential");

    private final MetadataPolicyMerger merger;
    private final JwtParser jwtParser;

    public PolicyEvaluator(MetadataPolicyMerger merger, JwtParser jwtParser) {
        this.merger = merger;
        this.jwtParser = jwtParser;
    }

    @SuppressWarnings("unchecked")
    public void validateCriticalOperators(List<String> crit, Map<String, Object> policy) {
        if (crit == null || crit.isEmpty()) return;
        for (String critOp : crit) {
            if (!KNOWN_OPERATORS.contains(critOp)) {
                throw new IllegalArgumentException("Unknown critical operator: " + critOp);
            }
            boolean found = false;
            if (policy != null) {
                for (Object entityTypeValue : policy.values()) {
                    if (!(entityTypeValue instanceof Map)) continue;
                    Map<String, Object> entityPolicy = (Map<String, Object>) entityTypeValue;
                    for (Object fieldValue : entityPolicy.values()) {
                        if (!(fieldValue instanceof Map)) continue;
                        Map<String, Object> operatorMap = (Map<String, Object>) fieldValue;
                        if (operatorMap.containsKey(critOp)) {
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
            }
            if (!found) {
                throw new IllegalArgumentException(
                        "Critical operator '" + critOp + "' declared but not used in policy");
            }
        }
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> evaluateChain(TrustChain chain) {
        List<String> statements = chain.statements();
        if (statements == null || statements.isEmpty()) return new LinkedHashMap<>();

        // statements[0] = leaf config, rest = subordinate statements + parent/anchor configs
        ParsedJwt leafConfig = jwtParser.parse(statements.get(0));
        Map<String, Object> leafMetadata = leafConfig.metadata() != null
                ? new LinkedHashMap<>(leafConfig.metadata())
                : new LinkedHashMap<>();

        // Collect metadata policies from superior statements (index 1..n), anchor first
        List<Map<String, Object>> policies = new ArrayList<>();
        for (int i = statements.size() - 1; i >= 1; i--) {
            ParsedJwt stmt = jwtParser.parse(statements.get(i));
            if (stmt.metadataPolicy() != null) {
                validateCriticalOperators(stmt.metadataPolicyCrit(), stmt.metadataPolicy());
                policies.add(stmt.metadataPolicy());
            }
        }

        // Merge all policies (first in list = highest priority = anchor)
        Map<String, Object> mergedPolicy = new LinkedHashMap<>();
        for (Map<String, Object> policy : policies) {
            mergedPolicy = merger.merge(mergedPolicy, policy);
        }

        // Apply merged policy to leaf metadata
        Map<String, Object> resolved = new LinkedHashMap<>(leafMetadata);
        for (Map.Entry<String, Object> entityTypeEntry : mergedPolicy.entrySet()) {
            String entityType = entityTypeEntry.getKey();
            if (!(entityTypeEntry.getValue() instanceof Map)) continue;
            Map<String, Object> entityPolicy = (Map<String, Object>) entityTypeEntry.getValue();

            if (!resolved.containsKey(entityType)) continue;
            Object entityMetadataObj = resolved.get(entityType);
            if (!(entityMetadataObj instanceof Map)) continue;
            Map<String, Object> entityMetadata = new LinkedHashMap<>((Map<String, Object>) entityMetadataObj);

            for (Map.Entry<String, Object> fieldEntry : entityPolicy.entrySet()) {
                String field = fieldEntry.getKey();
                if (!(fieldEntry.getValue() instanceof Map)) continue;
                Map<String, Object> operatorMap = (Map<String, Object>) fieldEntry.getValue();
                Object current = entityMetadata.get(field);
                Object applied = merger.applyOperators(operatorMap, current);
                entityMetadata.put(field, applied);
            }

            resolved.put(entityType, entityMetadata);
        }

        return resolved;
    }
}
