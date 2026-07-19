package com.tda.core.analysis.pattern;

import com.tda.core.analysis.classify.YamlMini;
import com.tda.core.model.ThreadState;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * One declarative detection rule from a {@code rules.yaml} file. The bundled frame-scan
 * detectors and user site packs are the same machinery: a {@code match} block (frames,
 * thread-name regex, states, min count, persistence, cpu condition) and an {@code emit}
 * side (id, title template, severity cap, recommendation).
 */
public record Rule(
        String id,
        String title,             // may contain {count} and {dump}
        Finding.Severity severity, // the CAP; CRITICAL additionally needs criticalThreads
        Integer warnThreads,       // below this count the finding degrades to INFO (optional)
        Integer criticalThreads,   // count needed to actually reach a CRITICAL cap (optional)
        String recommendation,
        List<String> frames,       // any frame contains any needle (empty = no frame test)
        Pattern threadNameRegex,   // nullable
        Set<ThreadState> states,   // empty = any state
        int minThreads,            // per-dump floor (default 1)
        Integer persistDumps,      // matched thread keys must persist >= K consecutive dumps
        String cpuDelta) {         // null | "any" | "zero" | "spinning"

    public static List<Rule> loadBundled() {
        try (InputStream in = Rule.class.getResourceAsStream("/rules.yaml")) {
            if (in == null) throw new IllegalStateException("rules.yaml missing from classpath");
            return parse(new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read bundled rules.yaml", e);
        }
    }

    public static List<Rule> loadFile(Path file) throws IOException {
        return parse(new BufferedReader(new StringReader(Files.readString(file))));
    }

    /** Bundled rules plus user files; a user rule with a bundled id replaces it. */
    public static List<Rule> merged(List<Path> userFiles) throws IOException {
        Map<String, Rule> byId = new LinkedHashMap<>();
        for (Rule r : loadBundled()) byId.put(r.id(), r);
        if (userFiles != null) {
            for (Path f : userFiles) {
                for (Rule r : loadFile(f)) byId.put(r.id(), r);
            }
        }
        return new ArrayList<>(byId.values());
    }

    @SuppressWarnings("unchecked")
    public static List<Rule> parse(BufferedReader reader) throws IOException {
        List<Rule> out = new ArrayList<>();
        for (Map<String, Object> item : YamlMini.parseItems(reader, "rules")) {
            String id = str(item, "id");
            String title = str(item, "title");
            String sev = str(item, "severity");
            String rec = str(item, "recommendation");
            if (id == null || title == null || sev == null || rec == null) {
                throw new IOException("rule " + (id != null ? id : item)
                        + ": id, title, severity, recommendation are required");
            }
            Finding.Severity severity;
            try {
                severity = Finding.Severity.valueOf(sev.toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new IOException("rule " + id + ": severity must be info|warning|critical, got " + sev);
            }
            Object matchObj = item.get("match");
            if (!(matchObj instanceof Map)) {
                throw new IOException("rule " + id + ": a match: block is required");
            }
            Map<String, Object> match = (Map<String, Object>) matchObj;
            List<String> frames = match.get("frames") instanceof List<?> l
                    ? List.copyOf((List<String>) l) : List.of();
            Pattern nameRegex = null;
            if (match.get("threadNameRegex") instanceof String s) {
                try {
                    nameRegex = Pattern.compile(s);
                } catch (PatternSyntaxException e) {
                    throw new IOException("rule " + id + ": bad threadNameRegex: " + e.getMessage());
                }
            }
            Set<ThreadState> states = EnumSet.noneOf(ThreadState.class);
            if (match.get("states") instanceof List<?> l) {
                for (Object o : l) {
                    try {
                        states.add(ThreadState.valueOf(String.valueOf(o).toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        throw new IOException("rule " + id + ": unknown state " + o);
                    }
                }
            }
            if (frames.isEmpty() && nameRegex == null && states.isEmpty()) {
                throw new IOException("rule " + id + ": match needs at least frames, "
                        + "threadNameRegex, or states");
            }
            String cpu = str(match, "cpuDelta");
            if (cpu != null && !cpu.matches("any|zero|spinning")) {
                throw new IOException("rule " + id + ": cpuDelta must be any|zero|spinning");
            }
            out.add(new Rule(id, title, severity,
                    intOrNull(item, "warnThreads"), intOrNull(item, "criticalThreads"), rec,
                    frames, nameRegex, states,
                    intOrNull(match, "minThreads") != null ? intOrNull(match, "minThreads") : 1,
                    intOrNull(match, "persistDumps"), cpu));
        }
        return out;
    }

    private static String str(Map<String, Object> m, String k) {
        return m.get(k) instanceof String s ? s : null;
    }

    private static Integer intOrNull(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (v == null) return null;
        try {
            return Integer.parseInt(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
