package com.example.federationdemo.controller;

import com.example.federationdemo.service.EntityStore;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@RestController
@Tag(name = "Federation", description = "OpenID Federation endpoints")
public class FederationController {

    private static final MediaType ENTITY_STATEMENT_JWT =
            MediaType.parseMediaType("application/entity-statement+jwt");

    private final EntityStore entityStore;

    @Value("${federation.base-url}")
    private String baseUrl;

    public FederationController(EntityStore entityStore) {
        this.entityStore = entityStore;
    }

    @Operation(summary = "Entity configuration JWT for anchor, intermediate or leaf")
    @GetMapping(value = "/{entity}/.well-known/openid-federation",
                produces = "application/entity-statement+jwt")
    public ResponseEntity<String> getEntityConfig(@PathVariable String entity) {
        String jwt = entityStore.getEntityConfig(entity);
        if (jwt == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(ENTITY_STATEMENT_JWT)
                .body(jwt);
    }

    @Operation(summary = "Subordinate statement from anchor or intermediate fetch endpoint")
    @GetMapping(value = "/{entity}/fetch",
                produces = "application/entity-statement+jwt")
    public ResponseEntity<String> fetchSubordinateStatement(
            @PathVariable String entity,
            @RequestParam String sub) {

        if ("leaf".equals(entity)) {
            return ResponseEntity.notFound().build();
        }

        String issuerEntityId = baseUrl + "/" + entity;
        String subjectEntityId;
        try {
            subjectEntityId = URLDecoder.decode(sub, StandardCharsets.UTF_8);
        } catch (Exception e) {
            subjectEntityId = sub;
        }

        String jwt = entityStore.getSubordinateStatement(issuerEntityId, subjectEntityId);
        if (jwt == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(ENTITY_STATEMENT_JWT)
                .body(jwt);
    }
}
