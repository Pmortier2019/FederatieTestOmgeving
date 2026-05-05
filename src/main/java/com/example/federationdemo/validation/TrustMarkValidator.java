package com.example.federationdemo.validation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Component
public class TrustMarkValidator {

    @SuppressWarnings("unused")
    private final RestTemplate restTemplate;

    public TrustMarkValidator(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void validateTrustMark(String trustMarkJwt, String expectedSub,
                                  String expectedTrustMarkType,
                                  ParsedJwt anchorConfig,
                                  PublicKey anchorPublicKey) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(trustMarkJwt);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            JOSEObjectType typ = signedJWT.getHeader().getType();
            if (typ == null || !"trust-mark+jwt".equals(typ.getType())) {
                throw new IllegalArgumentException(
                        "Trust mark typ must be 'trust-mark+jwt', got: " +
                                (typ != null ? typ.getType() : "null"));
            }

            if (claims.getIssuer() == null) {
                throw new IllegalArgumentException("Trust mark missing iss claim");
            }
            if (claims.getIssueTime() == null) {
                throw new IllegalArgumentException("Trust mark missing iat claim");
            }
            String trustMarkType = claims.getStringClaim("trust_mark_type");
            if (trustMarkType == null || trustMarkType.isBlank()) {
                throw new IllegalArgumentException("Trust mark missing trust_mark_type claim");
            }
            if (!expectedTrustMarkType.equals(trustMarkType)) {
                throw new IllegalArgumentException(
                        "Trust mark type mismatch: expected " + expectedTrustMarkType +
                                " but got " + trustMarkType);
            }
            if (!expectedSub.equals(claims.getSubject())) {
                throw new IllegalArgumentException(
                        "Trust mark sub mismatch: expected " + expectedSub +
                                " but got " + claims.getSubject());
            }

            long now = Instant.now().getEpochSecond();
            if (claims.getExpirationTime() != null) {
                long exp = claims.getExpirationTime().toInstant().getEpochSecond();
                if (exp <= now) {
                    throw new IllegalArgumentException("Trust mark is expired");
                }
            }

            PublicKey issuerPublicKey = resolveTrustMarkIssuerKey(claims, anchorConfig, anchorPublicKey);
            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) issuerPublicKey);
            if (!signedJWT.verify(verifier)) {
                throw new IllegalArgumentException("Trust mark signature verification failed");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Trust mark validation error: " + e.getMessage(), e);
        }
    }

    public void validateEntityHasTrustMark(ParsedJwt leafConfig, String requiredTrustMarkId,
                                           ParsedJwt anchorConfig,
                                           PublicKey anchorPublicKey) {
        List<Map<String, Object>> trustMarks = leafConfig.trustMarks();
        if (trustMarks == null || trustMarks.isEmpty()) {
            throw new IllegalArgumentException(
                    "Entity has no trust marks; required: " + requiredTrustMarkId);
        }

        String trustMarkJwt = null;
        for (Map<String, Object> entry : trustMarks) {
            if (requiredTrustMarkId.equals(entry.get("id"))) {
                Object val = entry.get("trust_mark");
                if (val instanceof String s) {
                    trustMarkJwt = s;
                }
                break;
            }
        }

        if (trustMarkJwt == null) {
            throw new IllegalArgumentException(
                    "Required trust mark '" + requiredTrustMarkId + "' not found in entity config");
        }

        validateTrustMark(trustMarkJwt, leafConfig.sub(), requiredTrustMarkId, anchorConfig, anchorPublicKey);
    }

    @SuppressWarnings("unchecked")
    private PublicKey resolveTrustMarkIssuerKey(JWTClaimsSet trustMarkClaims,
                                                ParsedJwt anchorConfig,
                                                PublicKey anchorPublicKey) throws Exception {
        String trustMarkType = trustMarkClaims.getStringClaim("trust_mark_type");
        String trustMarkIssuer = trustMarkClaims.getIssuer();

        Map<String, Object> owners = (Map<String, Object>) anchorConfig.rawPayload().get("trust_mark_owners");
        Map<String, Object> owner = owners != null
                ? (Map<String, Object>) owners.get(trustMarkType)
                : null;
        String ownerSub = owner != null ? (String) owner.get("sub") : anchorConfig.sub();

        if (trustMarkIssuer.equals(ownerSub)) {
            return owner != null && owner.get("jwks") instanceof Map<?, ?> ownerJwks
                    ? extractFirstEcKey((Map<String, Object>) ownerJwks)
                    : anchorPublicKey;
        }

        Object delegationObj = trustMarkClaims.getClaim("delegation");
        if (!(delegationObj instanceof String delegationJwt)) {
            throw new IllegalArgumentException(
                    "Trust mark issuer is not owner and delegation claim is missing");
        }
        if (owner == null || !(owner.get("jwks") instanceof Map<?, ?> ownerJwks)) {
            throw new IllegalArgumentException(
                    "Trust mark owner for '" + trustMarkType + "' not found in trust anchor");
        }

        SignedJWT delegation = SignedJWT.parse(delegationJwt);
        JOSEObjectType typ = delegation.getHeader().getType();
        if (typ == null || !"trust-mark-delegation+jwt".equals(typ.getType())) {
            throw new IllegalArgumentException(
                    "Trust mark delegation typ must be 'trust-mark-delegation+jwt'");
        }

        JWTClaimsSet delegationClaims = delegation.getJWTClaimsSet();
        if (!ownerSub.equals(delegationClaims.getIssuer())) {
            throw new IllegalArgumentException("Trust mark delegation iss does not match owner");
        }
        if (!trustMarkIssuer.equals(delegationClaims.getSubject())) {
            throw new IllegalArgumentException("Trust mark delegation sub does not match issuer");
        }
        if (!trustMarkType.equals(delegationClaims.getStringClaim("trust_mark_type"))) {
            throw new IllegalArgumentException("Trust mark delegation type does not match trust mark");
        }
        if (delegationClaims.getIssueTime() == null) {
            throw new IllegalArgumentException("Trust mark delegation missing iat claim");
        }
        long now = Instant.now().getEpochSecond();
        if (delegationClaims.getExpirationTime() != null
                && delegationClaims.getExpirationTime().toInstant().getEpochSecond() <= now) {
            throw new IllegalArgumentException("Trust mark delegation is expired");
        }

        PublicKey ownerKey = extractFirstEcKey((Map<String, Object>) ownerJwks);
        if (!delegation.verify(new ECDSAVerifier((ECPublicKey) ownerKey))) {
            throw new IllegalArgumentException("Trust mark delegation signature verification failed");
        }

        Map<String, Object> issuerJwks = (Map<String, Object>) delegationClaims.getClaim("jwks");
        if (issuerJwks == null) {
            throw new IllegalArgumentException("Trust mark delegation missing delegated issuer jwks");
        }
        return extractFirstEcKey(issuerJwks);
    }

    @SuppressWarnings("unchecked")
    private PublicKey extractFirstEcKey(Map<String, Object> jwks) throws Exception {
        if (jwks == null || !(jwks.get("keys") instanceof List<?> keys) || keys.isEmpty()) {
            throw new IllegalArgumentException("JWKS contains no keys");
        }
        return JWK.parse((Map<String, Object>) keys.get(0)).toECKey().toECPublicKey();
    }
}
