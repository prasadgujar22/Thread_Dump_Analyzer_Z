package com.tda.core.parse;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedStackTrace;
import jdk.jfr.consumer.RecordedThread;
import jdk.jfr.consumer.RecordingFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Turns a JFR recording into high-resolution synthetic thread dumps: execution samples are
 * bucketed into time slices (each slice becomes one {@link ThreadDump}) and fed to the
 * unchanged comparative engine - the same findings and charts, but with hundreds of data
 * points instead of 3-5. Events are streamed via {@link RecordingFile#readEvent()}; the
 * whole recording is never held in memory.
 */
public final class JfrLoader {

    /** Hard cap on synthetic dumps; the slice widens automatically to stay under it. */
    static final int MAX_SLICES = 300;

    public record JfrResult(DumpSeries series,
                            List<Map<String, Object>> contention,   // ThreadPark + MonitorEnter aggregate
                            List<Map<String, Object>> pinned,       // VirtualThreadPinned events
                            int executionSamples, Duration effectiveSlice) {}

    public static boolean looksLikeJfr(Path file) {
        if (file.getFileName().toString().endsWith(".jfr")) return true;
        try (InputStream in = Files.newInputStream(file)) {
            byte[] magic = in.readNBytes(4);
            return magic.length == 4 && magic[0] == 'F' && magic[1] == 'L' && magic[2] == 'R'
                    && magic[3] == 0;
        } catch (IOException e) {
            return false;
        }
    }

    public JfrResult load(Path file, Duration slice) throws IOException {
        // sliceStartMillis -> (threadKey -> latest sample in that slice)
        TreeMap<Long, Map<String, Sample>> slices = new TreeMap<>();
        Map<String, Contended> contention = new LinkedHashMap<>();
        List<Map<String, Object>> pinned = new ArrayList<>();
        long sliceMs = Math.max(100, slice.toMillis());
        int samples = 0;

        try (RecordingFile rf = new RecordingFile(file)) {
            while (rf.hasMoreEvents()) {
                RecordedEvent e = rf.readEvent();
                String type = e.getEventType().getName();
                switch (type) {
                    case "jdk.ExecutionSample", "jdk.NativeMethodSample" -> {
                        RecordedThread t = e.hasField("sampledThread")
                                ? e.getThread("sampledThread") : e.getThread();
                        RecordedStackTrace st = e.getStackTrace();
                        if (t == null || st == null) continue;
                        samples++;
                        long bucket = e.getStartTime().toEpochMilli() / sliceMs * sliceMs;
                        slices.computeIfAbsent(bucket, k -> new LinkedHashMap<>())
                                .put(threadKey(t), new Sample(t, frames(st)));
                    }
                    case "jdk.ThreadPark" -> aggregate(contention, "park",
                            className(e, "parkedClass"), e.getDuration());
                    case "jdk.JavaMonitorEnter" -> aggregate(contention, "monitor-enter",
                            className(e, "monitorClass"), e.getDuration());
                    case "jdk.VirtualThreadPinned" -> {
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("durationMs", e.getDuration().toNanos() / 1_000_000.0);
                        RecordedStackTrace st = e.getStackTrace();
                        if (st != null) row.put("frames", cap(frames(st), 12));
                        RecordedThread t = e.getThread();
                        if (t != null) row.put("thread", displayName(t));
                        if (pinned.size() < 100) pinned.add(row);
                    }
                    default -> { /* not interesting */ }
                }
            }
        }

        // widen slices if the recording produced too many buckets
        long effectiveMs = sliceMs;
        while (slices.size() > MAX_SLICES) {
            effectiveMs *= 2;
            TreeMap<Long, Map<String, Sample>> merged = new TreeMap<>();
            long finalMs = effectiveMs;
            slices.forEach((k, v) -> merged
                    .computeIfAbsent(k / finalMs * finalMs, x -> new LinkedHashMap<>())
                    .putAll(v));
            slices = merged;
        }

        DumpSeries series = new DumpSeries();
        int idx = 0;
        for (Map.Entry<Long, Map<String, Sample>> e : slices.entrySet()) {
            ThreadDump d = new ThreadDump();
            d.setTimestamp(Instant.ofEpochMilli(e.getKey()));
            d.setSourceName(file.getFileName() + "#slice-" + (idx++));
            d.setJvmBanner("JFR execution samples (" + effectiveMs + " ms slices)");
            for (Sample s : e.getValue().values()) d.threads().add(s.toThreadInfo());
            d.markSynchronizerSection(); // synthetic dumps shouldn't trigger the -l quality note
            series.add(d);
        }
        series.sortAndIndex();

        List<Map<String, Object>> contentionRows = new ArrayList<>();
        contention.values().stream()
                .sorted((a, b) -> Double.compare(b.totalMs, a.totalMs))
                .limit(30)
                .forEach(c -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("kind", c.kind);
                    row.put("class", c.className);
                    row.put("count", c.count);
                    row.put("totalMs", Math.round(c.totalMs * 100.0) / 100.0);
                    row.put("maxMs", Math.round(c.maxMs * 100.0) / 100.0);
                    contentionRows.add(row);
                });
        return new JfrResult(series, contentionRows, pinned, samples, Duration.ofMillis(effectiveMs));
    }

    private record Sample(RecordedThread thread, List<String> frames) {
        ThreadInfo toThreadInfo() {
            ThreadInfo t = new ThreadInfo();
            t.setName(displayName(thread));
            t.setJavaId(thread.getJavaThreadId() > 0 ? thread.getJavaThreadId() : null);
            if (thread.getOSThreadId() > 0) {
                t.setNid("0x" + Long.toHexString(thread.getOSThreadId()), thread.getOSThreadId());
            }
            t.setState(ThreadState.RUNNABLE); // it was on-CPU when sampled
            t.setStateDetail("RUNNABLE (sampled)");
            for (String f : frames) {
                StackFrame sf = StackFrame.parse("\tat " + f);
                if (sf != null) t.frames().add(sf);
            }
            return t;
        }
    }

    private record Contended(String kind, String className, long count, double totalMs, double maxMs) {}

    private void aggregate(Map<String, Contended> map, String kind, String cls, Duration dur) {
        if (cls == null || dur == null) return;
        double ms = dur.toNanos() / 1_000_000.0;
        map.merge(kind + "|" + cls, new Contended(kind, cls, 1, ms, ms),
                (a, b) -> new Contended(kind, cls, a.count + 1, a.totalMs + ms,
                        Math.max(a.maxMs, ms)));
    }

    private static String threadKey(RecordedThread t) {
        return t.getJavaThreadId() + "|" + displayName(t);
    }

    private static String displayName(RecordedThread t) {
        String n = t.getJavaName();
        if (n == null || n.isEmpty()) n = t.getOSName();
        if (n == null || n.isEmpty()) n = "thread-" + t.getJavaThreadId();
        return n;
    }

    private static String className(RecordedEvent e, String field) {
        try {
            var cls = e.getClass(field);
            return cls != null ? cls.getName() : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static List<String> frames(RecordedStackTrace st) {
        List<String> out = new ArrayList<>();
        for (RecordedFrame f : st.getFrames()) {
            if (out.size() >= 40) break;
            if (!f.isJavaFrame()) continue;
            String type = f.getMethod().getType() != null ? f.getMethod().getType().getName() : "?";
            int line = f.getLineNumber();
            out.add(type + "." + f.getMethod().getName()
                    + "(" + (line > 0 ? "line " + line : "Unknown Source") + ")");
        }
        return out;
    }

    private static List<String> cap(List<String> l, int n) {
        return l.size() <= n ? l : l.subList(0, n);
    }
}
