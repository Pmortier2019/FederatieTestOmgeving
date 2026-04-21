package com.example.federationdemo.controller;

import com.example.federationdemo.demo.DemoEvent;
import com.example.federationdemo.demo.LiveTracker;
import com.example.federationdemo.service.EntityStore;
import com.example.federationdemo.validation.JwtParser;
import com.example.federationdemo.validation.ParsedJwt;
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
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

@RestController
@Tag(name = "Federation", description = "OpenID Federation endpoints")
public class FederationController {

    private static final MediaType ENTITY_STATEMENT_JWT =
            MediaType.parseMediaType("application/entity-statement+jwt");

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Europe/Amsterdam"));

    private final EntityStore entityStore;
    private final LiveTracker liveTracker;
    private final JwtParser jwtParser;

    @Value("${federation.base-url}")
    private String baseUrl;

    public FederationController(EntityStore entityStore,
                                LiveTracker liveTracker,
                                JwtParser jwtParser) {
        this.entityStore = entityStore;
        this.liveTracker = liveTracker;
        this.jwtParser = jwtParser;
    }

    @Operation(summary = "Entity configuration JWT for anchor, intermediate or leaf")
    @GetMapping(value = "/{entity}/.well-known/openid-federation",
                produces = "application/entity-statement+jwt")
    public ResponseEntity<String> getEntityConfig(@PathVariable String entity) {
        String url = baseUrl + "/" + entity + "/.well-known/openid-federation";
        String jwt = entityStore.getEntityConfig(entity);
        if (jwt == null) {
            liveTracker.broadcast(DemoEvent.httpCallFailed(url, 404, "Entity niet bekend"));
            return ResponseEntity.notFound().build();
        }
        liveTracker.broadcast(buildHttpCallEvent(url, jwt));
        return ResponseEntity.ok().contentType(ENTITY_STATEMENT_JWT).body(jwt);
    }

    @Operation(summary = "Subordinate statement from anchor or intermediate fetch endpoint")
    @GetMapping(value = "/{entity}/fetch",
                produces = "application/entity-statement+jwt")
    public ResponseEntity<String> fetchSubordinateStatement(
            @PathVariable String entity,
            @RequestParam String sub) {

        String subjectEntityId;
        try {
            subjectEntityId = URLDecoder.decode(sub, StandardCharsets.UTF_8);
        } catch (Exception e) {
            subjectEntityId = sub;
        }
        String url = baseUrl + "/" + entity + "/fetch?sub=" + subjectEntityId;

        String issuerEntityId = baseUrl + "/" + entity;
        String jwt = entityStore.getSubordinateStatement(issuerEntityId, subjectEntityId);
        if (jwt == null) {
            liveTracker.broadcast(DemoEvent.httpCallFailed(url, 404,
                    "Geen subordinate statement voor " + subjectEntityId));
            return ResponseEntity.notFound().build();
        }
        liveTracker.broadcast(buildHttpCallEvent(url, jwt));
        return ResponseEntity.ok().contentType(ENTITY_STATEMENT_JWT).body(jwt);
    }

    private DemoEvent buildHttpCallEvent(String url, String jwt) {
        try {
            ParsedJwt parsed = jwtParser.parse(jwt);
            String exp = parsed.exp() != null
                    ? FMT.format(Instant.ofEpochSecond(parsed.exp())) : null;
            @SuppressWarnings("unchecked")
            List<String> hints = parsed.authorityHints();
            return DemoEvent.httpCall(url, 200, parsed.iss(), parsed.sub(), exp,
                    hints != null && !hints.isEmpty() ? hints : null);
        } catch (Exception e) {
            return DemoEvent.httpCall(url, 200, null, null, null, null);
        }
    }
}
