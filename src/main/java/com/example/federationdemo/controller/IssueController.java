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

    @Operation(summary = "Issue a signed credential JWT as the leaf entity",
               description = "Returns a JWT signed with the leaf private key. " +
                             "Use iss + kid to verify via the federation trust chain.")
    @PostMapping(value = "/issue", consumes = "application/json", produces = "application/json")
    public IssueResponse issue(@RequestBody IssueRequest request) {
        try {
            ECKey leafKey = entityStore.getEcKey("leaf");
            long now = Instant.now().getEpochSecond();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(baseUrl + "/leaf")
                    .subject(request.subject() != null ? request.subject() : "demo-subject")
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                    .claim("vc", Map.of(
                            "type", new String[]{"VerifiableCredential",
                                    request.credentialType() != null
                                            ? request.credentialType()
                                            : "DiplomaCertificate"},
                            "credentialSubject", Map.of(
                                    "id", request.subject() != null ? request.subject() : "demo-subject",
                                    "achievement", request.achievement() != null
                                            ? request.achievement()
                                            : "Bachelor of Science")))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("JWT"))
                    .keyID(leafKey.getKeyID())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(leafKey));

            return new IssueResponse(jwt.serialize(), baseUrl + "/leaf", leafKey.getKeyID());
        } catch (Exception e) {
            throw new RuntimeException("Failed to issue credential: " + e.getMessage(), e);
        }
    }

    public record IssueRequest(
            String subject,
            String credentialType,
            String achievement
    ) {}

    public record IssueResponse(
            String credentialJwt,
            String issuer,
            String kid
    ) {}
}
