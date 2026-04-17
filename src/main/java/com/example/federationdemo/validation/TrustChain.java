package com.example.federationdemo.validation;

import java.util.List;
import java.util.Map;

public record TrustChain(
    List<String> statements,
    Map<String, Object> resolvedMetadata
) {}
