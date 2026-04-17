package com.example.federationdemo.controller;

import com.example.federationdemo.validation.TrustChain;
import com.example.federationdemo.validation.TrustChainResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
            TrustChain chain = resolver.resolve(
                    request.issuerIdentifier(),
                    request.trustAnchorEntityId(),
                    null);
            return new VerifyResponse(true, request.issuerIdentifier(), null);
        } catch (Exception e) {
            return new VerifyResponse(false, null, e.getMessage());
        }
    }

    public record VerifyRequest(String issuerIdentifier, String trustAnchorEntityId) {}

    public record VerifyResponse(boolean trusted, String issuer, String error) {}
}
