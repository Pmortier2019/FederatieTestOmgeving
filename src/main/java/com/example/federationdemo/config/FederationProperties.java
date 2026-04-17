package com.example.federationdemo.config;

import java.util.List;
import java.util.Map;

public class FederationProperties {

    private String trustAnchorEntityId;
    private List<Map<String, Object>> trustAnchorJwks;

    public FederationProperties() {}

    public FederationProperties(String trustAnchorEntityId, List<Map<String, Object>> trustAnchorJwks) {
        this.trustAnchorEntityId = trustAnchorEntityId;
        this.trustAnchorJwks = trustAnchorJwks;
    }

    public String getTrustAnchorEntityId() { return trustAnchorEntityId; }
    public void setTrustAnchorEntityId(String trustAnchorEntityId) { this.trustAnchorEntityId = trustAnchorEntityId; }

    public List<Map<String, Object>> getTrustAnchorJwks() { return trustAnchorJwks; }
    public void setTrustAnchorJwks(List<Map<String, Object>> trustAnchorJwks) { this.trustAnchorJwks = trustAnchorJwks; }
}
