package com.example.federationdemo.controller;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.example.federationdemo.validation.TrustChain;
import com.example.federationdemo.validation.TrustChainResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

@RestController
@Tag(name = "Verify", description = "Trust chain verification")
public class VerifyController {

    private final TrustChainResolver resolver;

    public VerifyController(TrustChainResolver resolver) {
        this.resolver = resolver;
    }

    @Operation(summary = "Verify trust chain for an issuer against a trust anchor")
    @PostMapping(value = "/verify",
                 consumes = "application/json",
                 produces = "application/json")
    public VerifyResponse verify(@RequestBody VerifyRequest request) {
        try {
            SignedJWT credential = request.credentialJwt() != null && !request.credentialJwt().isBlank()
                    ? SignedJWT.parse(request.credentialJwt())
                    : null;
            String issuerIdentifier = request.issuerIdentifier();
            if ((issuerIdentifier == null || issuerIdentifier.isBlank()) && credential != null) {
                issuerIdentifier = credential.getJWTClaimsSet().getIssuer();
            }
            TrustChain chain = resolver.resolve(
                    issuerIdentifier,
                    request.trustAnchorEntityId(),
                    null);
            if (credential != null) {
                verifyCredentialAgainstResolvedMetadata(credential, chain);
            }
            return new VerifyResponse(true, issuerIdentifier, null);
        } catch (Exception e) {
            return new VerifyResponse(false, null, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void verifyCredentialAgainstResolvedMetadata(SignedJWT credential, TrustChain chain) throws Exception {
        Map<String, Object> resolvedMetadata = chain.resolvedMetadata();
        if (resolvedMetadata == null) {
            throw new IllegalArgumentException("Chain has no resolved metadata");
        }

        Map<String, Object> vcIssuer = (Map<String, Object>) resolvedMetadata.get("vc_issuer");
        if (vcIssuer == null || !(vcIssuer.get("jwks") instanceof Map<?, ?> jwksObj)) {
            throw new IllegalArgumentException("Resolved metadata has no vc_issuer.jwks");
        }

        Map<String, Object> jwks = (Map<String, Object>) jwksObj;
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("Resolved vc_issuer.jwks contains no keys");
        }

        String kid = credential.getHeader().getKeyID();
        ECPublicKey key = null;
        for (Map<String, Object> keyMap : keys) {
            if (kid == null || kid.equals(keyMap.get("kid"))) {
                key = JWK.parse(keyMap).toECKey().toECPublicKey();
                break;
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Credential kid is not allowed by resolved vc_issuer.jwks: " + kid);
        }
        if (!credential.verify(new ECDSAVerifier(key))) {
            throw new IllegalArgumentException("Credential signature does not verify with resolved vc_issuer.jwks");
        }

        Map<String, Object> openidCredentialIssuer =
                (Map<String, Object>) resolvedMetadata.get("openid_credential_issuer");
        if (openidCredentialIssuer != null
                && openidCredentialIssuer.get("credential_types_supported") instanceof List<?> supportedTypes) {
            List<String> credentialTypes = extractCredentialTypes(credential);
            boolean allowed = credentialTypes.stream().anyMatch(supportedTypes::contains);
            if (!allowed) {
                throw new IllegalArgumentException("Credential type " + credentialTypes +
                        " is not allowed by resolved metadata policy");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractCredentialTypes(SignedJWT credential) throws Exception {
        Object vcObj = credential.getJWTClaimsSet().getClaim("vc");
        if (!(vcObj instanceof Map<?, ?> vc)) {
            return List.of();
        }
        Object typeObj = vc.get("type");
        if (typeObj instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        if (typeObj instanceof String type) {
            return List.of(type);
        }
        return List.of();
    }

    public record VerifyRequest(String issuerIdentifier, String trustAnchorEntityId, String credentialJwt) {}

    public record VerifyResponse(boolean trusted, String issuer, String error) {}
}
