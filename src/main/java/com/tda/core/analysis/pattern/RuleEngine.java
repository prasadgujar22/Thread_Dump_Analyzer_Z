package com.tda.core.analysis.pattern;

import com.tda.core.analysis.series.SeriesIndex;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static com.tda.core.analysis.pattern.Finding.Severity.CRITICAL;
import static com.tda.core.analysis.pattern.Finding.Severity.INFO;
import static com.tda.core.analysis.pattern.Finding.Severity.WARNING;

/**
 * Runs declarative {@link Rule}s through the same findings pipeline as the native
 * detectors. Bundled rules (the migrated frame-scan built-ins) and user site packs are
 * literally the same machinery.
 */
public final class RuleEngine implements Pattern {

    private final List<Rule> rules;

    public RuleEngine(List<Rule> rules) {
        this.rules = rules;
    }

    @Override
    public List<Finding> detect(PatternContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (Rule rule : rules) {
            Finding f = evaluate(rule, ctx);
            if (f != null) out.add(f);
        }
        return out;
    }

    /** Evaluates one rule; visible for dry-run so the CLI can show what would fire. */
    public Finding evaluate(Rule rule, PatternContext ctx) {
        int worst = 0, worstDump = -1;
        List<ThreadInfo> worstMatches = List.of();
        List<Set<String>> matchedKeysPerDump = new ArrayList<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            List<ThreadInfo> matches = matchDump(rule, ctx.series().get(i));
            Set<String> keys = new LinkedHashSet<>();
            for (ThreadInfo t : matches) keys.add(SeriesIndex.keyOf(t));
            matchedKeysPerDump.add(keys);
            if (matches.size() > worst) {
                worst = matches.size();
                worstDump = i;
                worstMatches = matches;
            }
        }
        if (worst < rule.minThreads()) return null;

        String persistedKey = null;
        if (rule.persistDumps() != null) {
            persistedKey = findPersistentKey(matchedKeysPerDump, rule.persistDumps());
            if (persistedKey == null) return null;
        }
        String cpuNote = null;
        if (rule.cpuDelta() != null && !"any".equals(rule.cpuDelta())) {
            cpuNote = cpuConditionHolds(rule, ctx, persistedKey != null ? persistedKey
                    : worstMatches.isEmpty() ? null : SeriesIndex.keyOf(worstMatches.get(0)));
            if (cpuNote == null) return null;
        }

        Finding.Severity sev;
        if (rule.severity() == INFO) {
            sev = INFO;
        } else if (rule.warnThreads() != null && worst < rule.warnThreads()) {
            sev = INFO;
        } else if (rule.severity() == CRITICAL
                && rule.criticalThreads() != null && worst >= rule.criticalThreads()) {
            sev = CRITICAL;
        } else {
            sev = WARNING; // Rule 5: a CRITICAL cap without the impact threshold stays WARNING
        }

        String title = rule.title()
                .replace("{count}", String.valueOf(worst))
                .replace("{dump}", String.valueOf(worstDump));
        StringBuilder detail = new StringBuilder("Rule \"" + rule.id() + "\" matched " + worst
                + " thread(s) in dump " + worstDump);
        if (rule.persistDumps() != null) {
            detail.append(", persisting across ≥").append(rule.persistDumps())
                  .append(" consecutive dumps");
        }
        if (cpuNote != null) detail.append("; ").append(cpuNote);
        detail.append('.');

        List<String> names = new ArrayList<>();
        for (ThreadInfo t : worstMatches) {
            if (names.size() >= 15) break;
            names.add(t.name());
        }
        Finding f = new Finding(rule.id(), sev, title, detail.toString(), rule.recommendation())
                .evidence("dump", worstDump)
                .evidence("matchedThreads", worst)
                .evidence("threads", names)
                .evidence("confidence", rule.cpuDelta() != null || rule.persistDumps() != null
                        ? "high" : "medium")
                .evidence("whyNotFalsePositive", "every matched thread showed the rule's frame/"
                        + "state signature in the dump itself"
                        + (rule.persistDumps() != null ? " and persisted across dumps" : ""));
        if (!worstMatches.isEmpty()) {
            String frame = matchedFrame(rule, worstMatches.get(0));
            if (frame != null) f.evidence("frame", frame);
        }
        return f;
    }

    private List<ThreadInfo> matchDump(Rule rule, ThreadDump dump) {
        List<ThreadInfo> out = new ArrayList<>();
        for (ThreadInfo t : dump.javaThreads()) {
            if (!rule.states().isEmpty() && !rule.states().contains(t.state())) continue;
            if (rule.threadNameRegex() != null
                    && !rule.threadNameRegex().matcher(t.name()).matches()) continue;
            if (!rule.frames().isEmpty() && matchedFrame(rule, t) == null) continue;
            out.add(t);
        }
        return out;
    }

    private String matchedFrame(Rule rule, ThreadInfo t) {
        if (rule.frames().isEmpty()) return null;
        for (StackFrame f : t.frames()) {
            String sig = f.signature();
            for (String needle : rule.frames()) {
                if (sig.contains(needle)) return f.raw();
            }
        }
        return null;
    }

    /** A thread key matched in >= K consecutive dumps, or null. */
    private String findPersistentKey(List<Set<String>> perDump, int k) {
        Set<String> all = new HashSet<>();
        perDump.forEach(all::addAll);
        for (String key : all) {
            int run = 0;
            for (Set<String> dumpKeys : perDump) {
                run = dumpKeys.contains(key) ? run + 1 : 0;
                if (run >= k) return key;
            }
        }
        return null;
    }

    /** Evaluates the cpu condition for the given key; a note when it holds, else null. */
    private String cpuConditionHolds(Rule rule, PatternContext ctx, String key) {
        if (key == null) return null;
        ThreadInfo first = null, last = null;
        int firstIdx = -1, lastIdx = -1;
        for (int i = 0; i < ctx.series().size(); i++) {
            for (ThreadInfo t : ctx.series().get(i).javaThreads()) {
                if (SeriesIndex.keyOf(t).equals(key) && t.cpuMillis() != null) {
                    if (first == null) { first = t; firstIdx = i; }
                    last = t;
                    lastIdx = i;
                }
            }
        }
        if (first == null || last == first) return null; // no cpu data -> condition can't hold
        var t0 = ctx.series().get(firstIdx).timestamp();
        var t1 = ctx.series().get(lastIdx).timestamp();
        if (t0 == null || t1 == null || !t1.isAfter(t0)) return null;
        double wallMs = java.time.Duration.between(t0, t1).toMillis();
        double delta = last.cpuMillis() - first.cpuMillis();
        double ratio = delta / Math.max(1, wallMs);
        return switch (rule.cpuDelta()) {
            case "zero" -> ratio <= 0.05
                    ? String.format("cpu advanced only %.0f ms over %.0f ms wall (no progress)",
                                    delta, wallMs) : null;
            case "spinning" -> ratio >= 0.70
                    ? String.format("cpu advanced %.0f ms over %.0f ms wall (%.0f%% - busy loop)",
                                    delta, wallMs, ratio * 100) : null;
            default -> "";
        };
    }
}
