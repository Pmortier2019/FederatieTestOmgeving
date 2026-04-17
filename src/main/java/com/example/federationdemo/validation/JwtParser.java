package com.example.federationdemo.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class JwtParser {

    @SuppressWarnings("unchecked")
    public ParsedJwt parse(String jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            String iss = claims.getIssuer();
            String sub = claims.getSubject();
            Long iat = claims.getIssueTime() != null
                    ? claims.getIssueTime().toInstant().getEpochSecond() : null;
            Long exp = claims.getExpirationTime() != null
                    ? claims.getExpirationTime().toInstant().getEpochSecond() : null;

            Map<String, Object> jwks = (Map<String, Object>) claims.getClaim("jwks");
            Map<String, Object> metadata = (Map<String, Object>) claims.getClaim("metadata");
            Map<String, Object> metadataPolicy =
                    (Map<String, Object>) claims.getClaim("metadata_policy");
            List<String> metadataPolicyCrit =
                    (List<String>) claims.getClaim("metadata_policy_crit");
            List<String> authorityHints =
                    (List<String>) claims.getClaim("authority_hints");
            List<Map<String, Object>> trustMarks =
                    (List<Map<String, Object>>) claims.getClaim("trust_marks");
            Map<String, Object> constraints =
                    (Map<String, Object>) claims.getClaim("constraints");

            Map<String, Object> rawPayload = claims.toJSONObject();

            return new ParsedJwt(
                    jwt,
                    iss,
                    sub,
                    iat,
                    exp,
                    jwks,
                    metadata,
                    metadataPolicy,
                    metadataPolicyCrit != null ? metadataPolicyCrit : new ArrayList<>(),
                    authorityHints != null ? authorityHints : new ArrayList<>(),
                    trustMarks != null ? trustMarks : new ArrayList<>(),
                    constraints,
                    rawPayload);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT: " + e.getMessage(), e);
        }
    }
}
