package com.example.federationdemo.controller;

import com.nimbusds.jose.jwk.ECKey;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Eenmalig te gebruiken om stabiele sleutels naar Railway env vars te exporteren.
 * Bezoek /admin/export-keys op Railway, kopieer de waarden naar Railway → Variables.
 * Daarna zijn sleutels persistent over restarts.
 */
@RestController
@Tag(name = "Admin", description = "Sleutelbeheer")
public class AdminController {

    private final ECKey anchorKey;
    private final ECKey intermediateKey;
    private final ECKey leafKey;
    private final ECKey intermediate2Key;
    private final ECKey leaf2Key;
    private final ECKey rogueKey;
    private final ECKey leafExpiredKey;
    private final ECKey leafWrongSigningKey;
    private final ECKey leafWrongRegisteredKey;

    public AdminController(ECKey anchorKey, ECKey intermediateKey, ECKey leafKey,
                           ECKey intermediate2Key, ECKey leaf2Key, ECKey rogueKey,
                           ECKey leafExpiredKey, ECKey leafWrongSigningKey,
                           ECKey leafWrongRegisteredKey) {
        this.anchorKey             = anchorKey;
        this.intermediateKey       = intermediateKey;
        this.leafKey               = leafKey;
        this.intermediate2Key      = intermediate2Key;
        this.leaf2Key              = leaf2Key;
        this.rogueKey              = rogueKey;
        this.leafExpiredKey        = leafExpiredKey;
        this.leafWrongSigningKey   = leafWrongSigningKey;
        this.leafWrongRegisteredKey = leafWrongRegisteredKey;
    }

    @Operation(
        summary = "Exporteer alle private sleutels als Railway env vars",
        description = "Kopieer elke waarde naar Railway → Variables. " +
                      "Daarna blijven sleutels stabiel over restarts."
    )
    @GetMapping(value = "/admin/export-keys", produces = "application/json")
    public Map<String, String> exportKeys() throws Exception {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("ANCHOR_JWK",            anchorKey.toJSONString());
        result.put("INTERMEDIATE_JWK",      intermediateKey.toJSONString());
        result.put("LEAF_JWK",              leafKey.toJSONString());
        result.put("INTERMEDIATE2_JWK",     intermediate2Key.toJSONString());
        result.put("LEAF2_JWK",             leaf2Key.toJSONString());
        result.put("ROGUE_JWK",             rogueKey.toJSONString());
        result.put("LEAF_EXPIRED_JWK",      leafExpiredKey.toJSONString());
        result.put("LEAF_WRONGKEY_SIGN_JWK", leafWrongSigningKey.toJSONString());
        result.put("LEAF_WRONGKEY_REG_JWK", leafWrongRegisteredKey.toJSONString());
        return result;
    }
}
