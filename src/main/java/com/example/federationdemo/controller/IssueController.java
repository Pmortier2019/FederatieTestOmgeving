package com.example.federationdemo.controller;

import com.example.federationdemo.service.EntityStore;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

@RestController
@Tag(name = "Issue", description = "Credential issuance (demo)")
public class IssueController {

    private final EntityStore entityStore;

    @Value("${federation.base-url}")
    private String baseUrl;

    public IssueController(EntityStore entityStore) {
        this.entityStore = entityStore;
    }

    @Operation(
        summary = "Geef een gesigneerde credential JWT uit als leaf entity",
        description = """
            Geeft een JWT terug, gesigneerd door de opgegeven leaf.

            **issuer opties:**
            - `leaf` *(standaard)* — Hogeschool Utrecht, geldig pad via Surf → Overheid ✅
            - `leaf2` — Hogeschool Amsterdam, geldig pad via HBO-raad → Overheid ✅
            - `rogue` — Onbekende Instelling, niet opgenomen in de federatie ❌
            - `leaf-expired` — Verlopen Instelling, subordinate statement is verlopen ❌
            - `leaf-wrongkey` — Verkeerde Sleutel, chain klopt maar JWKS matcht niet met signatuur ❌
            """
    )
    @PostMapping(value = "/issue", consumes = "application/json", produces = "application/json")
    public IssueResponse issue(@RequestBody IssueRequest request) {
        try {
            String issuerName = request.issuer() != null ? request.issuer() : "leaf";
            String issuerUrl  = baseUrl + "/" + issuerName;

            ECKey signingKey = resolveSigningKey(issuerName);
            if (signingKey == null) {
                throw new IllegalArgumentException("Onbekende issuer: " + issuerName +
                        ". Geldige waarden: leaf, leaf2, rogue, leaf-expired, leaf-wrongkey");
            }

            long now = Instant.now().getEpochSecond();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuerUrl)
                    .subject(request.subject() != null ? request.subject() : "did:example:test")
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                    .claim("vc", Map.of(
                            "type", new String[]{"VerifiableCredential",
                                    request.credentialType() != null
                                            ? request.credentialType()
                                            : "DiplomaCertificate"},
                            "credentialSubject", Map.of(
                                    "id", request.subject() != null ? request.subject() : "did:example:test",
                                    "achievement", request.achievement() != null
                                            ? request.achievement()
                                            : "Bachelor of Science")))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("JWT"))
                    .keyID(signingKey.getKeyID())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(signingKey));

            return new IssueResponse(jwt.serialize(), issuerUrl, signingKey.getKeyID(), issuerName);
        } catch (Exception e) {
            throw new RuntimeException("Credential uitgifte mislukt: " + e.getMessage(), e);
        }
    }

    /**
     * Geeft de juiste signing key terug op basis van de issuer naam.
     * Let op: leaf-wrongkey gebruikt bewust een andere sleutel dan wat intermediate registreert.
     */
    private ECKey resolveSigningKey(String issuerName) {
        return switch (issuerName) {
            case "leaf"         -> entityStore.getEcKey("leaf");
            case "leaf2"        -> entityStore.getEcKey("leaf2");
            case "rogue"        -> entityStore.getEcKey("rogue");
            case "leaf-expired" -> entityStore.getEcKey("leaf-expired");
            case "leaf-wrongkey" -> entityStore.getEcKey("leaf-wrongkey-signing"); // bewust afwijkend
            default             -> null;
        };
    }

    public record IssueRequest(
            String subject,
            String credentialType,
            String achievement,
            String issuer
    ) {}

    public record IssueResponse(
            String credentialJwt,
            String issuer,
            String kid,
            String scenario
    ) {}
}
