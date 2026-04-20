package com.example.federationdemo.demo;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DemoEvent {

    private DemoEventType type;

    // HTTP_CALL
    private String url;
    private Integer statusCode;
    private String issField;
    private String subField;
    private String expField;
    private List<String> authorityHints;
    private String errorMessage;
    private String rawSnippet;

    // SCENARIO_START
    private Integer scenarioNummer;
    private String scenarioTitel;
    private String scenarioBeschrijving;

    // SCENARIO_RESULT / LOG
    private Boolean geslaagd;
    private String resultaat;
    private String toelichting;

    // SUMMARY
    private Integer aantalGeslaagd;
    private Integer aantalMislukt;

    private DemoEvent() {}

    public static DemoEvent scenarioStart(int nummer, String titel, String beschrijving) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.SCENARIO_START;
        e.scenarioNummer = nummer;
        e.scenarioTitel = titel;
        e.scenarioBeschrijving = beschrijving;
        return e;
    }

    public static DemoEvent httpCall(String url, int statusCode,
                                     String iss, String sub, String exp,
                                     List<String> authorityHints) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.HTTP_CALL;
        e.url = url;
        e.statusCode = statusCode;
        e.issField = iss;
        e.subField = sub;
        e.expField = exp;
        e.authorityHints = authorityHints;
        return e;
    }

    public static DemoEvent httpCallFailed(String url, int statusCode, String errorMessage) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.HTTP_CALL;
        e.url = url;
        e.statusCode = statusCode;
        e.errorMessage = errorMessage;
        return e;
    }

    public static DemoEvent httpCallError(String url, String errorMessage) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.HTTP_CALL;
        e.url = url;
        e.statusCode = 0;
        e.errorMessage = errorMessage;
        return e;
    }

    public static DemoEvent log(String toelichting) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.LOG;
        e.toelichting = toelichting;
        return e;
    }

    public static DemoEvent scenarioResult(boolean geslaagd, String resultaat, String toelichting) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.SCENARIO_RESULT;
        e.geslaagd = geslaagd;
        e.resultaat = resultaat;
        e.toelichting = toelichting;
        return e;
    }

    public static DemoEvent summary(int geslaagd, int mislukt) {
        DemoEvent e = new DemoEvent();
        e.type = DemoEventType.SUMMARY;
        e.aantalGeslaagd = geslaagd;
        e.aantalMislukt = mislukt;
        return e;
    }

    public DemoEventType getType() { return type; }
    public String getUrl() { return url; }
    public Integer getStatusCode() { return statusCode; }
    public String getIssField() { return issField; }
    public String getSubField() { return subField; }
    public String getExpField() { return expField; }
    public List<String> getAuthorityHints() { return authorityHints; }
    public String getErrorMessage() { return errorMessage; }
    public String getRawSnippet() { return rawSnippet; }
    public Integer getScenarioNummer() { return scenarioNummer; }
    public String getScenarioTitel() { return scenarioTitel; }
    public String getScenarioBeschrijving() { return scenarioBeschrijving; }
    public Boolean getGeslaagd() { return geslaagd; }
    public String getResultaat() { return resultaat; }
    public String getToelichting() { return toelichting; }
    public Integer getAantalGeslaagd() { return aantalGeslaagd; }
    public Integer getAantalMislukt() { return aantalMislukt; }
}
