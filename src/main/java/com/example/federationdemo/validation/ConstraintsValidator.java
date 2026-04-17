package com.example.federationdemo.validation;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class ConstraintsValidator {

    public void validate(Map<String, Object> constraints, int currentPathLength,
                         Map<String, Object> leafMetadata) {
        if (constraints == null) return;

        Object maxPathLength = constraints.get("max_path_length");
        if (maxPathLength instanceof Number n) {
            if (currentPathLength > n.intValue()) {
                throw new IllegalArgumentException(
                        "max_path_length constraint violated: path length " +
                        currentPathLength + " exceeds maximum " + n.intValue());
            }
        }

        @SuppressWarnings("unchecked")
        List<String> allowedTypes = (List<String>) constraints.get("allowed_leaf_entity_types");
        if (allowedTypes != null && leafMetadata != null) {
            boolean hasAllowedType = allowedTypes.stream()
                    .anyMatch(leafMetadata::containsKey);
            if (!hasAllowedType) {
                throw new IllegalArgumentException(
                        "allowed_leaf_entity_types constraint violated: leaf has none of " +
                        allowedTypes);
            }
        }
    }
}
