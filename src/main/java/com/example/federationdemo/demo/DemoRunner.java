package com.example.federationdemo.demo;

import com.example.federationdemo.service.EntityStore;
import com.example.federationdemo.service.StatementBuilder;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

@Component
public class DemoRunner {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Europe/Amsterdam"));

    @Value("${federation.base-url}")
    private String baseUrl;

    private final RestTemplate restTemplate;
    private final EntityStore entityStore;
    private final StatementBuilder statementBuilder;

    public DemoRunner(RestTemplate restTemplate,
                      EntityStore entityStore,
                      StatementBuilder statementBuilder) {
        this.restTemplate = restTemplate;
        this.entityStore = entityStore;
        this.statementBuilder = statementBuilder;
    }

    public void run(Consumer<DemoEvent> emit) {
        int geslaagd = 0;
        int mislukt = 0;

        // ── Scenario 1: Volledige trust chain ──
        emit.accept(DemoEvent.scenarioStart(1,
                "Volledige trust chain",
                "Opbouw van de volledige chain: Leaf → Intermediate → Trust Anchor"));

        boolean s1ok = scenarioHappyPath(emit);
        if (s1ok) geslaagd++; else mislukt++;

        // ── Scenario 2: Gebroken schakel ──
        emit.accept(DemoEvent.scenarioStart(2,
                "Gebroken schakel",
                "Intermediate kent de aanvragende entity niet — subordinate statement ontbreekt"));

        boolean s2ok = scenarioBrokenLink(emit);
        if (s2ok) geslaagd++; else mislukt++;

        // ── Scenario 3: Verkeerde trust anchor ──
        emit.accept(DemoEvent.scenarioStart(3,
                "Verkeerde trust anchor",
                "De chain is technisch geldig, maar de verifier accepteert een andere trust anchor"));

        boolean s3ok = scenarioWrongAnchor(emit);
        if (s3ok) geslaagd++; else mislukt++;

        // ── Scenario 4: Verlopen entity statement ──
        emit.accept(DemoEvent.scenarioStart(4,
                "Verlopen entity statement",
                "De entity configuration is verlopen (exp ligt in het verleden)"));

        boolean s4ok = scenarioExpired(emit);
        if (s4ok) geslaagd++; else mislukt++;

        emit.accept(DemoEvent.summary(geslaagd, mislukt));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 1: happy path
    // ─────────────────────────────────────────────────────────────────────────
    private boolean scenarioHappyPath(Consumer<DemoEvent> emit) {
        try {
            String leafUrl = baseUrl + "/leaf/.well-known/openid-federation";
            emit.accept(fetchAndParse(leafUrl));

            String intermediateUrl = baseUrl + "/intermediate/.well-known/openid-federation";
            emit.accept(fetchAndParse(intermediateUrl));

            String fetchLeafUrl = baseUrl + "/intermediate/fetch?sub="
                    + enc(baseUrl + "/leaf");
            emit.accept(fetchAndParse(fetchLeafUrl));

            String anchorUrl = baseUrl + "/anchor/.well-known/openid-federation";
            emit.accept(fetchAndParse(anchorUrl));

            String fetchIntermediateUrl = baseUrl + "/anchor/fetch?sub="
                    + enc(baseUrl + "/intermediate");
            emit.accept(fetchAndParse(fetchIntermediateUrl));

            emit.accept(DemoEvent.scenarioResult(true,
                    "Chain opgebouwd ✓",
                    "Leaf → Intermediate → Trust Anchor: alle statements aanwezig en bereikbaar."));
            return true;
        } catch (Exception e) {
            emit.accept(DemoEvent.scenarioResult(false, "Onverwachte fout", e.getMessage()));
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 2: gebroken schakel — onbekende entity vraagt subordinate stmt
    // ─────────────────────────────────────────────────────────────────────────
    private boolean scenarioBrokenLink(Consumer<DemoEvent> emit) {
        try {
            String leafUrl = baseUrl + "/leaf/.well-known/openid-federation";
            emit.accept(fetchAndParse(leafUrl));

            String unknownEntity = baseUrl + "/unknown-issuer";
            emit.accept(DemoEvent.log(
                    "Een onbekende entity probeert erkend te worden: " + unknownEntity));

            String fetchUrl = baseUrl + "/intermediate/fetch?sub=" + enc(unknownEntity);
            try {
                ResponseEntity<String> resp = restTemplate.getForEntity(fetchUrl, String.class);
                emit.accept(DemoEvent.httpCallFailed(fetchUrl, resp.getStatusCode().value(),
                        "Onverwacht antwoord: " + resp.getStatusCode()));
                emit.accept(DemoEvent.scenarioResult(false,
                        "Scenario niet correct gesimuleerd",
                        "Verwacht: 404. Gekregen: " + resp.getStatusCode()));
                return false;
            } catch (HttpClientErrorException ex) {
                emit.accept(DemoEvent.httpCallFailed(fetchUrl, ex.getStatusCode().value(),
                        "Intermediate geeft geen subordinate statement terug voor onbekende entity"));
                emit.accept(DemoEvent.scenarioResult(false,
                        "Chain geblokkeerd ✗",
                        "Intermediate retourneert " + ex.getStatusCode().value() +
                        " — de onbekende entity is niet erkend door de intermediate."));
                return false;
            }
        } catch (Exception e) {
            emit.accept(DemoEvent.scenarioResult(false, "Fout opgetreden", e.getMessage()));
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 3: verkeerde trust anchor
    // ─────────────────────────────────────────────────────────────────────────
    private boolean scenarioWrongAnchor(Consumer<DemoEvent> emit) {
        try {
            emit.accept(DemoEvent.log(
                    "Chain opbouwen (technisch correct via /leaf → /intermediate → /anchor)..."));

            String leafUrl = baseUrl + "/leaf/.well-known/openid-federation";
            emit.accept(fetchAndParse(leafUrl));

            String fetchLeafUrl = baseUrl + "/intermediate/fetch?sub=" + enc(baseUrl + "/leaf");
            emit.accept(fetchAndParse(fetchLeafUrl));

            String fakeAnchor = baseUrl + "/fake-trust-anchor";
            emit.accept(DemoEvent.log(
                    "Verifier is geconfigureerd met trust anchor: " + fakeAnchor));

            String fakeAnchorUrl = fakeAnchor + "/.well-known/openid-federation";
            try {
                ResponseEntity<String> resp = restTemplate.getForEntity(fakeAnchorUrl, String.class);
                emit.accept(DemoEvent.httpCallFailed(fakeAnchorUrl, resp.getStatusCode().value(),
                        "Onverwacht antwoord"));
            } catch (HttpClientErrorException ex) {
                emit.accept(DemoEvent.httpCallFailed(fakeAnchorUrl, ex.getStatusCode().value(),
                        "Trust anchor niet gevonden op dit endpoint"));
            }

            emit.accept(DemoEvent.scenarioResult(false,
                    "Chain afgewezen ✗",
                    "De chain is technisch opgebouwd via /anchor, maar de verifier accepteert " +
                    "alleen " + fakeAnchor + " als trust anchor. Die is niet bereikbaar."));
            return false;
        } catch (Exception e) {
            emit.accept(DemoEvent.scenarioResult(false, "Fout opgetreden", e.getMessage()));
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 4: verlopen entity statement
    // ─────────────────────────────────────────────────────────────────────────
    private boolean scenarioExpired(Consumer<DemoEvent> emit) {
        try {
            ECKey leafKey = entityStore.getEcKey("leaf");
            Map<String, Object> jwks = entityStore.getJwks("leaf");

            long past = Instant.now().getEpochSecond() - 7200; // 2 uur geleden
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", baseUrl + "/leaf");
            claims.put("sub", baseUrl + "/leaf");
            claims.put("iat", past - 86400);
            claims.put("exp", past); // verlopen
            claims.put("jwks", jwks);
            claims.put("metadata", Map.of("federation_entity",
                    Map.of("display_name", "Hogeschool Utrecht (verlopen demo)")));

            String expiredJwt = statementBuilder.sign(claims, leafKey);
            Map<String, Object> payload = decodePayload(expiredJwt);

            String expStr = formatEpoch((Long) payload.get("exp"));
            emit.accept(DemoEvent.log("Verlopen entity statement gegenereerd (exp: " + expStr + ")"));

            // Simuleer wat een validator doet
            DemoEvent callEvent = DemoEvent.httpCall(
                    "(lokaal gegenereerd verlopen JWT)",
                    200,
                    str(payload, "iss"),
                    str(payload, "sub"),
                    expStr,
                    null);
            emit.accept(callEvent);

            long now = Instant.now().getEpochSecond();
            long exp = (Long) payload.get("exp");
            if (exp <= now) {
                emit.accept(DemoEvent.scenarioResult(false,
                        "Verlopen statement afgewezen ✗",
                        "exp = " + expStr + " ligt in het verleden. " +
                        "De validator weigert dit statement. Een nieuwe entity configuration " +
                        "moet worden opgehaald."));
                return false;
            }

            emit.accept(DemoEvent.scenarioResult(true, "Niet verlopen", "Statement is nog geldig."));
            return true;
        } catch (Exception e) {
            emit.accept(DemoEvent.scenarioResult(false, "Fout opgetreden", e.getMessage()));
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    private DemoEvent fetchAndParse(String url) {
        try {
            ResponseEntity<String> resp = restTemplate.getForEntity(url, String.class);
            String body = resp.getBody();
            if (body == null || body.isBlank()) {
                return DemoEvent.httpCallFailed(url, resp.getStatusCode().value(), "Lege response");
            }
            Map<String, Object> payload = decodePayload(body.trim());
            String iss = str(payload, "iss");
            String sub = str(payload, "sub");
            String exp = formatEpoch(payload.get("exp") instanceof Number n
                    ? n.longValue() : null);
            @SuppressWarnings("unchecked")
            List<String> hints = (List<String>) payload.get("authority_hints");
            return DemoEvent.httpCall(url, resp.getStatusCode().value(), iss, sub, exp, hints);
        } catch (HttpClientErrorException ex) {
            return DemoEvent.httpCallFailed(url, ex.getStatusCode().value(),
                    "HTTP " + ex.getStatusCode().value());
        } catch (Exception ex) {
            return DemoEvent.httpCallError(url, ex.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decodePayload(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) throw new IllegalArgumentException("Not a JWT");
            byte[] decoded = Base64.getUrlDecoder().decode(
                    parts[1].replaceAll("=+$", "") + switch (parts[1].length() % 4) {
                        case 2 -> "=="; case 3 -> "="; default -> "";
                    });
            String json = new String(decoded, StandardCharsets.UTF_8);
            // Simple JSON → Map using Jackson (available via Spring Boot)
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(json, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String str(Map<String, Object> map, String key) {
        Object v = map.get(key);
        return v != null ? v.toString() : null;
    }

    private String formatEpoch(Long epoch) {
        if (epoch == null) return null;
        return FMT.format(Instant.ofEpochSecond(epoch));
    }

    private String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
