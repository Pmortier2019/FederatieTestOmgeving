package com.example.federationdemo.validation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;

@Component
public class EntityStatementValidator {

    public void validate(ParsedJwt parsed) {
        long now = Instant.now().getEpochSecond();

        if (parsed.exp() == null || parsed.exp() <= now) {
            throw new IllegalArgumentException("JWT is expired or missing exp claim");
        }
        if (parsed.iat() == null) {
            throw new IllegalArgumentException("JWT is missing iat claim");
        }
        if (parsed.iss() == null || parsed.iss().isBlank()) {
            throw new IllegalArgumentException("JWT is missing iss claim");
        }
        if (parsed.sub() == null || parsed.sub().isBlank()) {
            throw new IllegalArgumentException("JWT is missing sub claim");
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(parsed.rawJwt());
            String alg = signedJWT.getHeader().getAlgorithm().getName();
            if ("none".equalsIgnoreCase(alg)) {
                throw new IllegalArgumentException("JWT algorithm must not be 'none'");
            }
            JOSEObjectType typ = signedJWT.getHeader().getType();
            if (typ == null || !"entity-statement+jwt".equals(typ.getType())) {
                throw new IllegalArgumentException(
                        "JWT typ header must be 'entity-statement+jwt', got: " +
                        (typ != null ? typ.getType() : "null"));
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT for validation: " + e.getMessage(), e);
        }
    }

    public void validate(ParsedJwt parsed, PublicKey verificationKey) {
        validate(parsed);
        try {
            SignedJWT signedJWT = SignedJWT.parse(parsed.rawJwt());
            ECDSAVerifier verifier = new ECDSAVerifier((ECPublicKey) verificationKey);
            if (!signedJWT.verify(verifier)) {
                throw new IllegalArgumentException("JWT signature verification failed");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Signature verification error: " + e.getMessage(), e);
        }
    }
}
