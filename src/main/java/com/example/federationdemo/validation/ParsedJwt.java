package com.example.federationdemo.validation;

import java.util.List;
import java.util.Map;

public record ParsedJwt(
    String rawJwt,
    String iss,
    String sub,
    Long iat,
    Long exp,
    Map<String, Object> jwks,
    Map<String, Object> metadata,
    Map<String, Object> metadataPolicy,
    List<String> metadataPolicyCrit,
    List<String> authorityHints,
    List<Map<String, Object>> trustMarks,
    Map<String, Object> constraints,
    Map<String, Object> rawPayload
) {}
