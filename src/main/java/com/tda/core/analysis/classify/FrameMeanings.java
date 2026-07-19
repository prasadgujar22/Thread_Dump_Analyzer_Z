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
 * The frame->meaning knowledge base: turns stack frames into a plain-English "what is this
 * thread doing" line with a category (db-wait, mq-wait, http-wait, ...). Bundled as
 * {@code frame-meanings.yaml}; site-extensible with {@code --frame-meanings} exactly like
 * the idle patterns.
 */
public final class FrameMeanings {

    /** How many top frames are examined (waits sit deep under park/read wrappers). */
    public static final int TOP_FRAMES = 10;

    public record Meaning(String name, String category, String activity, String narrative,
                          List<String> frames) {}

    private final List<Meaning> entries;

    private FrameMeanings(List<Meaning> entries) { this.entries = entries; }

    public List<Meaning> entries() { return entries; }

    public static FrameMeanings loadDefault() {
        try (InputStream in = FrameMeanings.class.getResourceAsStream("/frame-meanings.yaml")) {
            if (in == null) throw new IllegalStateException("frame-meanings.yaml missing from classpath");
            return new FrameMeanings(parse(new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read bundled frame-meanings.yaml", e);
        }
    }

    /** Defaults plus a user file; user entries match first, same-name entries override. */
    public static FrameMeanings withUserFile(Path file) throws IOException {
        List<Meaning> user = parse(new BufferedReader(new StringReader(Files.readString(file))));
        Map<String, Meaning> merged = new LinkedHashMap<>();
        for (Meaning m : user) merged.put(m.name(), m);
        for (Meaning m : loadDefault().entries) merged.putIfAbsent(m.name(), m);
        return new FrameMeanings(new ArrayList<>(merged.values()));
    }

    /** The first matching meaning across the top frames, or null. */
    public Meaning meaningFor(ThreadInfo t) {
        int n = Math.min(TOP_FRAMES, t.frames().size());
        for (int i = 0; i < n; i++) {
            StackFrame f = t.frames().get(i);
            Meaning m = meaningForFrame(f.signature());
            if (m != null) return m;
        }
        return null;
    }

    /** Meaning for one frame signature (used for call-stack tree annotation), or null. */
    public Meaning meaningForFrame(String signature) {
        for (Meaning m : entries) {
            for (String needle : m.frames()) {
                if (signature.contains(needle)) return m;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    static List<Meaning> parse(BufferedReader reader) throws IOException {
        List<Meaning> out = new ArrayList<>();
        for (Map<String, Object> item : YamlMini.parseItems(reader, "meanings")) {
            String name = str(item, "name");
            String category = str(item, "category");
            String activity = str(item, "activity");
            Object frames = item.get("frames");
            if (name == null || category == null || activity == null
                    || !(frames instanceof List) || ((List<String>) frames).isEmpty()) {
                throw new IOException("frame-meanings entry " + item
                        + " needs name, category, activity, and a non-empty frames list");
            }
            out.add(new Meaning(name, category, activity,
                    item.get("narrative") instanceof String s ? s : "",
                    List.copyOf((List<String>) frames)));
        }
        return out;
    }

    private static String str(Map<String, Object> m, String k) {
        return m.get(k) instanceof String s ? s : null;
    }
}
