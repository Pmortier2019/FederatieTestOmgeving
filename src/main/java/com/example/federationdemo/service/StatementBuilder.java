package com.example.federationdemo.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class StatementBuilder {

    public String sign(Map<String, Object> claims, ECKey signerKey) {
        try {
            long now = Instant.now().getEpochSecond();

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                switch (entry.getKey()) {
                    case "iss" -> builder.issuer((String) entry.getValue());
                    case "sub" -> builder.subject((String) entry.getValue());
                    case "iat" -> builder.issueTime(
                            Date.from(Instant.ofEpochSecond((Long) entry.getValue())));
                    case "exp" -> builder.expirationTime(
                            Date.from(Instant.ofEpochSecond((Long) entry.getValue())));
                    default -> builder.claim(entry.getKey(), entry.getValue());
                }
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("entity-statement+jwt"))
                    .keyID(signerKey.getKeyID())
                    .build();

            SignedJWT jwt = new SignedJWT(header, builder.build());
            jwt.sign(new ECDSASigner(signerKey));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign JWT", e);
        }
    }
}
