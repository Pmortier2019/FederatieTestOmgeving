package com.example.federationdemo.validation;

import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class MetadataPolicyMerger {

    @SuppressWarnings("unchecked")
    public Object applyOperators(Map<String, Object> operatorMap, Object currentValue) {
        if (operatorMap == null) return currentValue;

        Object result = currentValue;

        if (operatorMap.containsKey("value")) {
            return operatorMap.get("value");
        }

        if (operatorMap.containsKey("default") && result == null) {
            result = operatorMap.get("default");
        }

        if (operatorMap.containsKey("add") && result instanceof List<?> list) {
            List<Object> merged = new ArrayList<>(list);
            Object toAdd = operatorMap.get("add");
            if (toAdd instanceof List<?> addList) {
                for (Object item : addList) {
                    if (!merged.contains(item)) merged.add(item);
                }
            }
            result = merged;
        }

        if (operatorMap.containsKey("subset_of") && result instanceof List<?> list) {
            List<Object> allowed = (List<Object>) operatorMap.get("subset_of");
            List<Object> filtered = new ArrayList<>();
            for (Object item : list) {
                if (allowed.contains(item)) filtered.add(item);
            }
            result = filtered;
        }

        if (operatorMap.containsKey("superset_of") && result instanceof List<?> list) {
            List<Object> required = (List<Object>) operatorMap.get("superset_of");
            for (Object req : required) {
                if (!list.contains(req)) {
                    throw new IllegalArgumentException(
                            "superset_of constraint violated: missing required value " + req);
                }
            }
        }

        if (operatorMap.containsKey("one_of")) {
            List<Object> allowed = (List<Object>) operatorMap.get("one_of");
            if (result != null && !allowed.contains(result)) {
                throw new IllegalArgumentException(
                        "one_of constraint violated: value " + result +
                        " not in " + allowed);
            }
        }

        if (operatorMap.containsKey("essential")) {
            boolean essential = Boolean.TRUE.equals(operatorMap.get("essential"));
            if (essential && result == null) {
                throw new IllegalArgumentException(
                        "essential constraint violated: required value is null");
            }
        }

        return result;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> merge(Map<String, Object> policy1, Map<String, Object> policy2) {
        if (policy1 == null && policy2 == null) return new LinkedHashMap<>();
        if (policy1 == null) return new LinkedHashMap<>(policy2);
        if (policy2 == null) return new LinkedHashMap<>(policy1);

        Map<String, Object> result = new LinkedHashMap<>(policy2);

        for (Map.Entry<String, Object> entry : policy1.entrySet()) {
            String entityType = entry.getKey();
            if (!(entry.getValue() instanceof Map)) continue;
            Map<String, Object> p1EntityPolicy = (Map<String, Object>) entry.getValue();

            if (!result.containsKey(entityType)) {
                result.put(entityType, new LinkedHashMap<>(p1EntityPolicy));
                continue;
            }

            Map<String, Object> p2EntityPolicy = (Map<String, Object>) result.get(entityType);
            Map<String, Object> mergedEntityPolicy = new LinkedHashMap<>(p2EntityPolicy);

            for (Map.Entry<String, Object> fieldEntry : p1EntityPolicy.entrySet()) {
                String field = fieldEntry.getKey();
                if (!(fieldEntry.getValue() instanceof Map)) continue;
                Map<String, Object> p1Ops = (Map<String, Object>) fieldEntry.getValue();

                if (!mergedEntityPolicy.containsKey(field)) {
                    mergedEntityPolicy.put(field, new LinkedHashMap<>(p1Ops));
                    continue;
                }

                Map<String, Object> p2Ops = (Map<String, Object>) mergedEntityPolicy.get(field);
                Map<String, Object> mergedOps = new LinkedHashMap<>(p2Ops);
                // policy1 wins on value and one_of
                for (String op : List.of("value", "one_of")) {
                    if (p1Ops.containsKey(op)) {
                        mergedOps.put(op, p1Ops.get(op));
                    }
                }
                mergedEntityPolicy.put(field, mergedOps);
            }

            result.put(entityType, mergedEntityPolicy);
        }

        return result;
    }
}
