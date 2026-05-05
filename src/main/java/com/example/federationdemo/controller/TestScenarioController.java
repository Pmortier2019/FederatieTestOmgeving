package com.example.federationdemo.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.List;

@RestController
@Tag(name = "Test scenarios", description = "Runnable OpenID Federation test scenarios")
public class TestScenarioController {

    private final IssueController issueController;
    private final VerifyController verifyController;

    @Value("${federation.base-url}")
    private String baseUrl;

    public TestScenarioController(IssueController issueController,
                                  VerifyController verifyController) {
        this.issueController = issueController;
        this.verifyController = verifyController;
    }

    @Operation(summary = "List all available federation test scenarios")
    @GetMapping(value = "/test-scenarios", produces = "application/json")
    public List<TestScenarioView> list() {
        return scenarios().stream()
                .sorted(Comparator.comparingInt(TestScenario::id))
                .map(this::toView)
                .toList();
    }

    @Operation(summary = "Issue and verify one test scenario against its expected result")
    @PostMapping(value = "/test-scenarios/{id}/run", produces = "application/json")
    public ScenarioRunResult run(@PathVariable int id,
                                 @RequestParam(defaultValue = "true") boolean includeCredential) {
        TestScenario scenario = findScenario(id);
        String trustAnchor = trustAnchorFor(scenario);
        String credentialJwt = null;

        try {
            IssueController.IssueResponse issue = issueController.issue(new IssueController.IssueRequest(
                    "did:example:test",
                    scenario.credentialType(),
                    "Bachelor of Science",
                    scenario.issuer()));
            credentialJwt = issue.credentialJwt();

            VerifyController.VerifyResponse verify = verifyController.verify(new VerifyController.VerifyRequest(
                    baseUrl + "/" + scenario.issuer(),
                    trustAnchor,
                    credentialJwt));

            boolean actualTrusted = verify.trusted();
            boolean passed = actualTrusted == scenario.expectedTrusted();
            return new ScenarioRunResult(
                    scenario.id(),
                    scenario.title(),
                    scenario.category(),
                    scenario.expectedTrusted(),
                    actualTrusted,
                    passed,
                    scenario.issuer(),
                    trustAnchor,
                    traceFor(scenario),
                    includeCredential ? credentialJwt : null,
                    verify.error());
        } catch (Exception e) {
            return new ScenarioRunResult(
                    scenario.id(),
                    scenario.title(),
                    scenario.category(),
                    scenario.expectedTrusted(),
                    false,
                    false,
                    scenario.issuer(),
                    trustAnchor,
                    traceFor(scenario),
                    includeCredential ? credentialJwt : null,
                    e.getMessage());
        }
    }

    @Operation(summary = "Run all federation test scenarios")
    @PostMapping(value = "/test-scenarios/run-all", produces = "application/json")
    public RunAllResult runAll(@RequestParam(defaultValue = "false") boolean includeCredentials) {
        List<ScenarioRunResult> results = scenarios().stream()
                .sorted(Comparator.comparingInt(TestScenario::id))
                .map(s -> run(s.id(), includeCredentials))
                .toList();
        long passed = results.stream().filter(ScenarioRunResult::passed).count();
        return new RunAllResult(results.size(), (int) passed, results.size() - (int) passed, results);
    }

    private TestScenario findScenario(int id) {
        return scenarios().stream()
                .filter(s -> s.id() == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown test scenario: " + id));
    }

    private TestScenarioView toView(TestScenario scenario) {
        return new TestScenarioView(
                scenario.id(),
                scenario.title(),
                scenario.category(),
                scenario.expectedTrusted(),
                scenario.issuer(),
                trustAnchorFor(scenario),
                scenario.credentialType(),
                scenario.description(),
                traceFor(scenario));
    }

    private String trustAnchorFor(TestScenario scenario) {
        return baseUrl + scenario.anchorPath();
    }

    private ChainTrace traceFor(TestScenario scenario) {
        String issuer = baseUrl + "/" + scenario.issuer();
        String trustAnchor = trustAnchorFor(scenario);
        return new ChainTrace(
                issuer,
                trustAnchor,
                scenario.credentialType(),
                issuer + "/.well-known/openid-federation",
                authorityHintsFor(scenario),
                fetchCallsFor(scenario),
                policySummaryFor(scenario));
    }

    private List<String> authorityHintsFor(TestScenario scenario) {
        return switch (scenario.issuer()) {
            case "leaf2" -> List.of(baseUrl + "/intermediate2");
            case "leaf-multihint" -> List.of(baseUrl + "/nonexistent-intermediate", baseUrl + "/intermediate");
            case "leaf-nohint" -> List.of(baseUrl + "/nonexistent-1", baseUrl + "/nonexistent-2");
            case "leaf-deep" -> List.of(baseUrl + "/inter-depth-1");
            case "leaf-maxpath" -> List.of(baseUrl + "/intermediate-maxpath");
            case "leaf-chain3" -> List.of(baseUrl + "/inter-chain3-1");
            case "leaf-chain5" -> List.of(baseUrl + "/inter-chain5-1");
            case "leaf-chain10" -> List.of(baseUrl + "/inter-chain10-1");
            case "leaf-5hints" -> List.of(
                    baseUrl + "/nonexistent-h1", baseUrl + "/nonexistent-h2",
                    baseUrl + "/nonexistent-h3", baseUrl + "/nonexistent-h4",
                    baseUrl + "/intermediate");
            case "leaf-10hints" -> List.of(
                    baseUrl + "/nonexistent-h1", baseUrl + "/nonexistent-h2",
                    baseUrl + "/nonexistent-h3", baseUrl + "/nonexistent-h4",
                    baseUrl + "/nonexistent-h5", baseUrl + "/nonexistent-h6",
                    baseUrl + "/nonexistent-h7", baseUrl + "/nonexistent-h8",
                    baseUrl + "/nonexistent-h9", baseUrl + "/intermediate");
            case "leaf-10hints-fail" -> List.of(
                    baseUrl + "/nonexistent-h1", baseUrl + "/nonexistent-h2",
                    baseUrl + "/nonexistent-h3", baseUrl + "/nonexistent-h4",
                    baseUrl + "/nonexistent-h5", baseUrl + "/nonexistent-h6",
                    baseUrl + "/nonexistent-h7", baseUrl + "/nonexistent-h8",
                    baseUrl + "/nonexistent-h9", baseUrl + "/nonexistent-h10");
            default -> List.of(baseUrl + "/intermediate");
        };
    }

    private List<String> fetchCallsFor(TestScenario scenario) {
        String issuer = baseUrl + "/" + scenario.issuer();
        return switch (scenario.issuer()) {
            case "leaf2" -> List.of(
                    baseUrl + "/intermediate2/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate2");
            case "leaf-multihint" -> List.of(
                    baseUrl + "/nonexistent-intermediate/.well-known/openid-federation",
                    baseUrl + "/intermediate/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate");
            case "leaf-nohint" -> List.of(
                    baseUrl + "/nonexistent-1/.well-known/openid-federation",
                    baseUrl + "/nonexistent-2/.well-known/openid-federation");
            case "leaf-deep" -> List.of(
                    baseUrl + "/inter-depth-1/fetch?sub=" + issuer,
                    baseUrl + "/inter-depth-2/fetch?sub=" + baseUrl + "/inter-depth-1",
                    baseUrl + "/inter-depth-3/fetch?sub=" + baseUrl + "/inter-depth-2",
                    baseUrl + "/inter-depth-4/fetch?sub=" + baseUrl + "/inter-depth-3",
                    baseUrl + "/inter-depth-5/fetch?sub=" + baseUrl + "/inter-depth-4",
                    baseUrl + "/inter-depth-6/fetch?sub=" + baseUrl + "/inter-depth-5",
                    baseUrl + "/inter-depth-7/fetch?sub=" + baseUrl + "/inter-depth-6",
                    baseUrl + "/inter-depth-8/fetch?sub=" + baseUrl + "/inter-depth-7",
                    baseUrl + "/inter-depth-9/fetch?sub=" + baseUrl + "/inter-depth-8",
                    baseUrl + "/inter-depth-10/fetch?sub=" + baseUrl + "/inter-depth-9",
                    baseUrl + "/inter-depth-11/fetch?sub=" + baseUrl + "/inter-depth-10");
            case "leaf-maxpath" -> List.of(
                    baseUrl + "/intermediate-maxpath/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate-maxpath");
            case "leaf-chain3" -> List.of(
                    baseUrl + "/inter-chain3-1/fetch?sub=" + issuer,
                    baseUrl + "/inter-chain3-2/fetch?sub=" + baseUrl + "/inter-chain3-1",
                    baseUrl + "/inter-chain3-3/fetch?sub=" + baseUrl + "/inter-chain3-2",
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/inter-chain3-3");
            case "leaf-chain5" -> List.of(
                    baseUrl + "/inter-chain5-1/fetch?sub=" + issuer,
                    baseUrl + "/inter-chain5-2/fetch?sub=" + baseUrl + "/inter-chain5-1",
                    baseUrl + "/inter-chain5-3/fetch?sub=" + baseUrl + "/inter-chain5-2",
                    baseUrl + "/inter-chain5-4/fetch?sub=" + baseUrl + "/inter-chain5-3",
                    baseUrl + "/inter-chain5-5/fetch?sub=" + baseUrl + "/inter-chain5-4",
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/inter-chain5-5");
            case "leaf-chain10" -> List.of(
                    baseUrl + "/inter-chain10-1/fetch?sub=" + issuer,
                    baseUrl + "/inter-chain10-2/fetch?sub=" + baseUrl + "/inter-chain10-1",
                    baseUrl + "/inter-chain10-3/fetch?sub=" + baseUrl + "/inter-chain10-2",
                    baseUrl + "/inter-chain10-4/fetch?sub=" + baseUrl + "/inter-chain10-3",
                    baseUrl + "/inter-chain10-5/fetch?sub=" + baseUrl + "/inter-chain10-4",
                    baseUrl + "/inter-chain10-6/fetch?sub=" + baseUrl + "/inter-chain10-5",
                    baseUrl + "/inter-chain10-7/fetch?sub=" + baseUrl + "/inter-chain10-6",
                    baseUrl + "/inter-chain10-8/fetch?sub=" + baseUrl + "/inter-chain10-7",
                    baseUrl + "/inter-chain10-9/fetch?sub=" + baseUrl + "/inter-chain10-8",
                    baseUrl + "/inter-chain10-10/fetch?sub=" + baseUrl + "/inter-chain10-9",
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/inter-chain10-10");
            case "leaf-5hints" -> List.of(
                    baseUrl + "/nonexistent-h1/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h2/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h3/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h4/.well-known/openid-federation",
                    baseUrl + "/intermediate/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate");
            case "leaf-10hints" -> List.of(
                    baseUrl + "/nonexistent-h1/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h2/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h3/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h4/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h5/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h6/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h7/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h8/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h9/.well-known/openid-federation",
                    baseUrl + "/intermediate/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate");
            case "leaf-10hints-fail" -> List.of(
                    baseUrl + "/nonexistent-h1/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h2/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h3/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h4/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h5/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h6/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h7/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h8/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h9/.well-known/openid-federation",
                    baseUrl + "/nonexistent-h10/.well-known/openid-federation");
            default -> List.of(
                    baseUrl + "/intermediate/fetch?sub=" + issuer,
                    baseUrl + "/anchor/fetch?sub=" + baseUrl + "/intermediate");
        };
    }

    private String policySummaryFor(TestScenario scenario) {
        return switch (scenario.issuer()) {
            case "leaf-policy-type" -> "metadata_policy subset_of laat alleen StudentCardCredential toe; DiplomaCertificate wordt afgewezen.";
            case "leaf-policy-jwks" -> "metadata_policy value overschrijft vc_issuer.jwks met een andere key.";
            case "leaf-policy-crit" -> "metadata_policy_crit bevat unknown_operator; verifier moet afwijzen.";
            case "leaf-policy-type-ok" -> "metadata_policy subset_of bevat DiplomaCertificate; verifier mag accepteren.";
            case "leaf-policy-jwks-ok" -> "metadata_policy value zet vc_issuer.jwks op dezelfde geldige key.";
            case "leaf-policy-crit-ok" -> "metadata_policy_crit bevat bekende operator subset_of.";
            default -> null;
        };
    }

    private List<TestScenario> scenarios() {
        return List.of(
                new TestScenario(1, "Geldig pad - Hogeschool Utrecht", "valid", true,
                        "leaf", "/anchor", "DiplomaCertificate",
                        "Leaf via Surf naar de Nederlandse Overheid."),
                new TestScenario(2, "Geldig pad - Hogeschool Amsterdam", "valid", true,
                        "leaf2", "/anchor", "DiplomaCertificate",
                        "Tweede geldig pad via HBO-raad naar dezelfde trust anchor."),
                new TestScenario(3, "Rogue issuer - niet in de federatie", "integrity", false,
                        "rogue", "/anchor", "DiplomaCertificate",
                        "Issuer heeft geen subordinate statement bij de intermediate."),
                new TestScenario(4, "Verlopen subordinate statement", "integrity", false,
                        "leaf-expired", "/anchor", "DiplomaCertificate",
                        "Subordinate statement is verlopen."),
                new TestScenario(5, "Verkeerde sleutel in subordinate statement", "integrity", false,
                        "leaf-wrongkey", "/anchor", "DiplomaCertificate",
                        "Resolved vc_issuer.jwks bevat niet de credential signing key."),
                new TestScenario(6, "Metadata policy - niet-toegestaan credential type", "policy", false,
                        "leaf-policy-type", "/anchor", "DiplomaCertificate",
                        "Policy beperkt credential_types_supported zodat DiplomaCertificate niet overblijft."),
                new TestScenario(7, "Metadata policy - JWKS overschreven", "policy", false,
                        "leaf-policy-jwks", "/anchor", "DiplomaCertificate",
                        "Policy value overschrijft vc_issuer.jwks met een andere sleutel."),
                new TestScenario(8, "Metadata policy - onbekende kritische operator", "policy", false,
                        "leaf-policy-crit", "/anchor", "DiplomaCertificate",
                        "metadata_policy_crit bevat een onbekende operator."),
                new TestScenario(9, "Twee authority hints - een kapot, een geldig", "authority", true,
                        "leaf-multihint", "/anchor", "DiplomaCertificate",
                        "Resolver moet na falende hint doorgaan naar de geldige hint."),
                new TestScenario(10, "Twee authority hints - beide ongeldig", "authority", false,
                        "leaf-nohint", "/anchor", "DiplomaCertificate",
                        "Geen authority hint leidt naar de trust anchor."),
                new TestScenario(11, "Geldig credential - verkeerd trust anchor opgegeven", "authority", false,
                        "leaf", "/rogue", "DiplomaCertificate",
                        "Credential is goed, maar verifier verwacht de verkeerde trust anchor."),
                new TestScenario(12, "Sub-claim in subordinate statement klopt niet", "integrity", false,
                        "leaf-subwrong", "/anchor", "DiplomaCertificate",
                        "Subordinate statement sub komt niet overeen met de leaf entity-id."),
                new TestScenario(13, "Chain te diep", "integrity", false,
                        "leaf-deep", "/anchor", "DiplomaCertificate",
                        "Chain overschrijdt de maximale diepte."),
                new TestScenario(14, "Constraints - max_path_length overschreden", "integrity", false,
                        "leaf-maxpath", "/anchor", "DiplomaCertificate",
                        "Trust anchor staat geen intermediate toe, maar er zit er wel een tussen."),
                new TestScenario(15, "Metadata policy - toegestaan credential type", "policy", true,
                        "leaf-policy-type-ok", "/anchor", "DiplomaCertificate",
                        "subset_of policy laat DiplomaCertificate toe."),
                new TestScenario(16, "Metadata policy - JWKS value blijft geldig", "policy", true,
                        "leaf-policy-jwks-ok", "/anchor", "DiplomaCertificate",
                        "value policy zet vc_issuer.jwks op dezelfde geldige sleutel."),
                new TestScenario(17, "Metadata policy crit - bekende operator", "policy", true,
                        "leaf-policy-crit-ok", "/anchor", "DiplomaCertificate",
                        "metadata_policy_crit gebruikt bekende operator subset_of."),
                new TestScenario(18, "Geldig pad - keten diepte 3", "depth", true,
                        "leaf-chain3", "/anchor", "DiplomaCertificate",
                        "Leaf via 3 intermediates naar trust anchor — geldige diepe keten."),
                new TestScenario(19, "Geldig pad - keten diepte 5", "depth", true,
                        "leaf-chain5", "/anchor", "DiplomaCertificate",
                        "Leaf via 5 intermediates naar trust anchor — geldige diepe keten."),
                new TestScenario(20, "Geldig pad - keten diepte 10", "depth", true,
                        "leaf-chain10", "/anchor", "DiplomaCertificate",
                        "Leaf via 10 intermediates naar trust anchor — maximale geldige diepte."),
                new TestScenario(21, "Vijf authority hints - 4 kapot, 1 geldig", "authority", true,
                        "leaf-5hints", "/anchor", "DiplomaCertificate",
                        "Resolver probeert 4 ongeldige hints voordat de geldige hint slaagt."),
                new TestScenario(22, "Tien authority hints - 9 kapot, 1 geldig", "authority", true,
                        "leaf-10hints", "/anchor", "DiplomaCertificate",
                        "Resolver probeert 9 ongeldige hints voordat de geldige hint slaagt."),
                new TestScenario(23, "Tien authority hints - alle ongeldig", "authority", false,
                        "leaf-10hints-fail", "/anchor", "DiplomaCertificate",
                        "Geen van de 10 authority hints leidt naar de trust anchor.")
        );
    }

    public record TestScenario(
            int id,
            String title,
            String category,
            boolean expectedTrusted,
            String issuer,
            String anchorPath,
            String credentialType,
            String description) {}

    public record TestScenarioView(
            int id,
            String title,
            String category,
            boolean expectedTrusted,
            String issuer,
            String trustAnchorEntityId,
            String credentialType,
            String description,
            ChainTrace trace) {}

    public record ScenarioRunResult(
            int id,
            String title,
            String category,
            boolean expectedTrusted,
            boolean actualTrusted,
            boolean passed,
            String issuer,
            String trustAnchorEntityId,
            ChainTrace trace,
            String credentialJwt,
            String error) {}

    public record ChainTrace(
            String issuerIdentifier,
            String trustAnchorEntityId,
            String credentialType,
            String entityConfigurationUrl,
            List<String> authorityHints,
            List<String> expectedFetchCalls,
            String policySummary) {}

    public record RunAllResult(
            int total,
            int passed,
            int failed,
            List<ScenarioRunResult> results) {}
}
