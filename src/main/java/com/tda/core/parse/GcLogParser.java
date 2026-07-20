package com.tda.core.parse;

import java.io.BufferedReader;
import java.io.IOException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts stop-the-world pause windows from GC logs - just enough of each format to know
 * WHEN the application was stopped, for how long, and why:
 * <ul>
 *   <li>unified logging (JDK 9+): {@code -Xlog:gc*}, {@code -Xlog:safepoint}</li>
 *   <li>JDK 8: {@code -XX:+PrintGCDetails -XX:+PrintGCDateStamps} and
 *       {@code Total time for which application threads were stopped} lines</li>
 * </ul>
 * Unparseable lines are skipped silently; a GC log is noisy by nature.
 */
public final class GcLogParser {

    public record PauseWindow(Instant start, double durationMs, String cause, String kind) {
        public Instant end() { return start.plusNanos((long) (durationMs * 1_000_000)); }
        public boolean covers(Instant t, long slackMillis) {
            return !t.isBefore(start.minusMillis(slackMillis))
                    && !t.isAfter(end().plusMillis(slackMillis));
        }
    }

    // [2026-07-16T14:10:01.234+0000][info][gc] GC(5) Pause Young (Normal) (G1 Evacuation Pause) ... 12.345ms
    private static final Pattern UNIFIED = Pattern.compile(
            "^\\[(?<ts>\\d{4}-\\d{2}-\\d{2}T[\\d:.+\\-]+)]\\[.*?(?<tag>gc|safepoint).*?](?<rest>.*)$");
    private static final Pattern UNIFIED_MS = Pattern.compile("(?<ms>\\d+(?:\\.\\d+)?)ms\\s*$");
    // one level of nesting so "(System.gc())" captures the inner parens too
    private static final Pattern PARENS = Pattern.compile("\\(((?:[^()]|\\([^()]*\\))*)\\)");
    private static final Pattern SAFEPOINT_NAME = Pattern.compile("Safepoint \"(?<name>[^\"]+)\"");
    private static final Pattern SAFEPOINT_TOTAL_NS = Pattern.compile("Total: (?<ns>\\d+) ns");
    private static final Pattern SAFEPOINT_AT_NS = Pattern.compile("At safepoint: (?<ns>\\d+) ns");
    // 2026-07-16T14:10:01.234+0000: 123.456: [GC (Allocation Failure) ..., 0.0123456 secs]
    private static final Pattern JDK8 = Pattern.compile(
            "^(?<ts>\\d{4}-\\d{2}-\\d{2}T[\\d:.+\\-]+): [\\d.]+: (?<rest>.*)$");
    // no end anchor: JDK 8 lines often continue with a "[Times: ...]" block
    private static final Pattern JDK8_SECS = Pattern.compile(", (?<secs>[\\d.]+) secs]");
    private static final Pattern JDK8_STOPPED = Pattern.compile(
            "Total time for which application threads were stopped: (?<secs>[\\d.]+) seconds");
    private static final DateTimeFormatter TS8 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    public List<PauseWindow> parse(BufferedReader reader) throws IOException {
        List<PauseWindow> out = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            PauseWindow w = parseLine(line);
            if (w != null) out.add(w);
        }
        out.sort((a, b) -> a.start().compareTo(b.start()));
        return out;
    }

    PauseWindow parseLine(String line) {
        Matcher u = UNIFIED.matcher(line);
        if (u.matches()) {
            Instant ts = parseIso(u.group("ts"));
            if (ts == null) return null;
            String rest = u.group("rest");
            if ("safepoint".equals(u.group("tag"))) {
                Matcher ns = SAFEPOINT_TOTAL_NS.matcher(rest);
                if (!ns.find()) ns = null;
                if (ns == null) {
                    Matcher at = SAFEPOINT_AT_NS.matcher(rest);
                    if (at.find()) ns = at;
                }
                if (ns != null) {
                    Matcher nm = SAFEPOINT_NAME.matcher(rest);
                    return new PauseWindow(ts, Long.parseLong(ns.group("ns")) / 1_000_000.0,
                            nm.find() ? nm.group("name") : "safepoint", "safepoint");
                }
                return null;
            }
            if (!rest.contains(" Pause ")) return null;
            Matcher ms = UNIFIED_MS.matcher(rest.trim());
            if (!ms.find()) return null;
            return new PauseWindow(ts, Double.parseDouble(ms.group("ms")),
                    unifiedCause(rest), "gc");
        }
        Matcher j = JDK8.matcher(line);
        if (j.matches()) {
            Instant ts = parseJdk8(j.group("ts"));
            if (ts == null) return null;
            String rest = j.group("rest");
            Matcher stopped = JDK8_STOPPED.matcher(rest);
            if (stopped.find()) {
                return new PauseWindow(ts, Double.parseDouble(stopped.group("secs")) * 1000.0,
                        "threads stopped", "safepoint");
            }
            if (rest.startsWith("[GC") || rest.startsWith("[Full GC")) {
                Matcher secs = JDK8_SECS.matcher(rest);
                if (!secs.find()) return null;
                Matcher cause = PARENS.matcher(rest);
                return new PauseWindow(ts, Double.parseDouble(secs.group("secs")) * 1000.0,
                        cause.find() ? cause.group(1) : (rest.startsWith("[Full") ? "Full GC" : "GC"),
                        "gc");
            }
        }
        return null;
    }

    /** "Pause Young (Normal) (G1 Evacuation Pause) 512M->128M(1024M)" -> "G1 Evacuation Pause" */
    private String unifiedCause(String rest) {
        String cause = "GC pause";
        Matcher p = PARENS.matcher(rest);
        while (p.find()) {
            String g = p.group(1);
            if (!g.matches("\\d+[KMGT]?B?")) cause = g; // skip heap-size parens
        }
        return cause;
    }

    private Instant parseIso(String s) {
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (Exception e) {
            try {
                return OffsetDateTime.parse(s, TS8).toInstant();
            } catch (Exception e2) {
                return null;
            }
        }
    }

    private Instant parseJdk8(String s) {
        try {
            return OffsetDateTime.parse(s, TS8).toInstant();
        } catch (Exception e) {
            return parseIso(s);
        }
    }
}
