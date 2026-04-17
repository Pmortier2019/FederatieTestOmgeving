package com.example.federationdemo.validation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSAVerifier;
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

    private final RestTemplate restTemplate;

    public TrustMarkValidator(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void validateTrustMark(String trustMarkJwt, String expectedSub,
                                   PublicKey issuerPublicKey) {
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

    @SuppressWarnings("unchecked")
    public void validateEntityHasTrustMark(ParsedJwt leafConfig, String requiredTrustMarkId,
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

        validateTrustMark(trustMarkJwt, leafConfig.sub(), anchorPublicKey);
    }
}
