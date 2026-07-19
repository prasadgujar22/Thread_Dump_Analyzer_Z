package com.tda.core.analysis.classify;

import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The idle-pattern knowledge base (Rule 1): threads whose top frames match a known
 * "waiting for work / waiting for events" pattern are classified idle and never reported
 * as stuck. Patterns ship as {@code idle-patterns.yaml} on the classpath; users extend or
 * override them per-site with {@code --idle-patterns <file>} - no rebuild needed.
 *
 * <p>The file is parsed with a strict dependency-free YAML subset (two-space indentation,
 * {@code patterns:} list of {@code name}/{@code label}/{@code frames}); this keeps the jar
 * free of third-party parsers.
 */
public final class IdlePatterns {

    /**
     * How many top frames are examined for a match. Modern JDKs bury the idle queue-take
     * under LockSupport/ForkJoinPool.managedBlock wrappers (~7 frames deep), so the window
     * is wider than the frames a human would read first.
     */
    public static final int TOP_FRAMES = 8;

    public record Entry(String name, String label, List<String> frames) {}

    private final List<Entry> entries;

    private IdlePatterns(List<Entry> entries) {
        this.entries = entries;
    }

    public List<Entry> entries() { return entries; }

    /** The bundled default knowledge base. */
    public static IdlePatterns loadDefault() {
        try (InputStream in = IdlePatterns.class.getResourceAsStream("/idle-patterns.yaml")) {
            if (in == null) throw new IllegalStateException("idle-patterns.yaml missing from classpath");
            return new IdlePatterns(parse(new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read bundled idle-patterns.yaml", e);
        }
    }

    /** Defaults plus a user file; user entries match first, same-name entries override. */
    public static IdlePatterns withUserFile(Path file) throws IOException {
        List<Entry> user = parse(new BufferedReader(new StringReader(Files.readString(file))));
        Map<String, Entry> merged = new LinkedHashMap<>();
        for (Entry e : user) merged.put(e.name(), e);
        for (Entry e : loadDefault().entries) merged.putIfAbsent(e.name(), e);
        return new IdlePatterns(new ArrayList<>(merged.values()));
    }

    /** The matching idle label for this thread, or null when it matches no pattern. */
    public String labelFor(ThreadInfo t) {
        int n = Math.min(TOP_FRAMES, t.frames().size());
        for (int i = 0; i < n; i++) {
            StackFrame f = t.frames().get(i);
            String sig = f.signature();
            for (Entry e : entries) {
                for (String needle : e.frames()) {
                    if (sig.contains(needle)) return e.label();
                }
            }
        }
        return null;
    }

    // ---- minimal YAML-subset parser: patterns: / - name: / label: / frames: / - value ----
    static List<Entry> parse(BufferedReader reader) throws IOException {
        List<Entry> out = new ArrayList<>();
        String name = null;
        String label = null;
        List<String> frames = null;
        boolean inFrames = false;
        String line;
        int lineNo = 0;
        while ((line = reader.readLine()) != null) {
            lineNo++;
            String t = stripComment(line).trim();
            if (t.isEmpty() || t.equals("patterns:")) continue;
            if (t.startsWith("- name:")) {
                flush(out, name, label, frames, lineNo);
                name = t.substring("- name:".length()).trim();
                label = null;
                frames = null;
                inFrames = false;
            } else if (t.startsWith("label:")) {
                label = unquote(t.substring("label:".length()).trim());
                inFrames = false;
            } else if (t.equals("frames:")) {
                frames = new ArrayList<>();
                inFrames = true;
            } else if (t.startsWith("- ") && inFrames && frames != null) {
                frames.add(unquote(t.substring(2).trim()));
            } else {
                throw new IOException("idle-patterns line " + lineNo + ": unrecognized entry \"" + t + "\"");
            }
        }
        flush(out, name, label, frames, lineNo);
        return out;
    }

    private static void flush(List<Entry> out, String name, String label, List<String> frames, int lineNo)
            throws IOException {
        if (name == null) return;
        if (label == null || frames == null || frames.isEmpty()) {
            throw new IOException("idle-patterns entry \"" + name + "\" (near line " + lineNo
                    + ") needs both a label and a non-empty frames list");
        }
        out.add(new Entry(name, label, List.copyOf(frames)));
    }

    private static String stripComment(String s) {
        int i = s.indexOf('#');
        return i >= 0 ? s.substring(0, i) : s;
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && (s.startsWith("\"") && s.endsWith("\"")
                || s.startsWith("'") && s.endsWith("'"))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }
}
