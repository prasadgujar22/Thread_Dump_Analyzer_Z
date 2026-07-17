package com.tda.core.analysis.pattern;

import java.util.LinkedHashMap;
import java.util.Map;

/** One severity-ranked finding with evidence and a concrete remediation. */
public final class Finding {

    public enum Severity { CRITICAL, WARNING, INFO }

    private final String id;             // stable pattern id, e.g. "deadlock", "pool-exhaustion"
    private final Severity severity;
    private final String title;
    private final String detail;
    private final String recommendation;
    private final Map<String, Object> evidence = new LinkedHashMap<>();

    public Finding(String id, Severity severity, String title, String detail, String recommendation) {
        this.id = id;
        this.severity = severity;
        this.title = title;
        this.detail = detail;
        this.recommendation = recommendation;
    }

    public Finding evidence(String key, Object value) {
        evidence.put(key, value);
        return this;
    }

    public Severity severity() { return severity; }

    public Map<String, Object> toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("severity", severity.name());
        m.put("title", title);
        m.put("detail", detail);
        m.put("recommendation", recommendation);
        m.put("evidence", evidence);
        return m;
    }
}
