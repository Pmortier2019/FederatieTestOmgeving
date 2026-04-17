package com.example.federationdemo.controller;

import com.example.federationdemo.service.EntityStore;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@Tag(name = "Debug", description = "Debug and info endpoints")
public class InfoController {

    private final EntityStore entityStore;

    @Value("${federation.base-url}")
    private String baseUrl;

    public InfoController(EntityStore entityStore) {
        this.entityStore = entityStore;
    }

    @Operation(summary = "Overview of all entities, JWKS and relations")
    @GetMapping(value = "/info", produces = "application/json")
    public Map<String, Object> info() {
        Map<String, Object> result = new LinkedHashMap<>();

        result.put("entities", List.of(
                entityInfo("anchor"),
                entityInfo("intermediate"),
                entityInfo("leaf")));

        result.put("hierarchy", Map.of(
                "leaf", baseUrl + "/leaf",
                "leaf_parent", baseUrl + "/intermediate",
                "intermediate_parent", baseUrl + "/anchor",
                "trust_anchor", baseUrl + "/anchor"));

        result.put("endpoints", Map.of(
                "anchor_config", baseUrl + "/anchor/.well-known/openid-federation",
                "intermediate_config", baseUrl + "/intermediate/.well-known/openid-federation",
                "leaf_config", baseUrl + "/leaf/.well-known/openid-federation",
                "anchor_fetch", baseUrl + "/anchor/fetch",
                "intermediate_fetch", baseUrl + "/intermediate/fetch",
                "swagger_ui", baseUrl + "/swagger-ui.html"));

        return result;
    }

    private Map<String, Object> entityInfo(String entity) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("entity", entity);
        info.put("entity_id", baseUrl + "/" + entity);
        info.put("jwks", entityStore.getJwks(entity));
        info.put("config_endpoint",
                baseUrl + "/" + entity + "/.well-known/openid-federation");
        return info;
    }
}
