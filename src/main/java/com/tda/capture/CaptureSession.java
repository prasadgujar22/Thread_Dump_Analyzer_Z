package com.tda.capture;

import com.tda.core.json.Json;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Runs a capture series against one pid: picks the first working strategy, reuses it for
 * every subsequent capture, writes analysis-ready files (first line = the timestamp the
 * parser already reads) plus manifest.json, and optionally a top -H snapshot per capture.
 */
public final class CaptureSession {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    public record CaptureResult(List<Path> dumpFiles, List<Path> topFiles,
                                Path manifest, String strategy) {}

    private final List<CaptureStrategy> chain;
    private final Exec exec;
    private final PrintStream log;

    public CaptureSession(List<CaptureStrategy> chain, Exec exec, PrintStream log) {
        this.chain = chain;
        this.exec = exec;
        this.log = log;
    }

    /** The default fallback chain for this platform. */
    public static CaptureSession standard(ProcFs proc, Exec exec, Path stdoutLog, PrintStream log) {
        return new CaptureSession(List.of(
                Strategies.targetJdkJcmd(proc, exec),
                Strategies.ownJdkJcmd(exec),
                Strategies.attachApi(),
                Strategies.sigquit(exec, stdoutLog)), exec, log);
    }

    public CaptureResult run(long pid, int count, Duration interval, Path outDir, boolean withTop)
            throws IOException, InterruptedException {
        Files.createDirectories(outDir);
        CaptureStrategy winner = null;
        List<Path> dumps = new ArrayList<>();
        List<Path> tops = new ArrayList<>();
        List<Object> manifestCaptures = new ArrayList<>();
        String jvmBanner = null;

        for (int i = 1; i <= count; i++) {
            LocalDateTime now = LocalDateTime.now();
            String text = null;
            if (winner == null) {
                for (CaptureStrategy s : chain) {
                    log.printf("capture %d/%d: trying strategy %s...%n", i, count, s.name());
                    Optional<String> r = s.tryCapture(pid);
                    if (r.isPresent()) {
                        winner = s;
                        text = r.get();
                        log.printf("capture %d/%d: strategy %s succeeded%n", i, count, s.name());
                        break;
                    }
                }
                if (winner == null) {
                    throw new IOException("every capture strategy failed for pid " + pid
                            + " - if the JVM logs to a file, retry with --stdout-log <path> "
                            + "(SIGQUIT dumps land on the target's stdout, e.g. catalina.out "
                            + "or the WebLogic .out file)");
                }
            } else {
                text = winner.tryCapture(pid).orElseThrow(() -> new IOException(
                        "strategy stopped working mid-series (target gone?)"));
            }

            String normalized = normalize(text, now);
            if (jvmBanner == null) jvmBanner = firstBanner(normalized);
            Path f = outDir.resolve(String.format("dump-%02d-%s.txt", i, FILE_TS.format(now)));
            Files.writeString(f, normalized, StandardCharsets.UTF_8);
            dumps.add(f);
            log.printf("capture %d/%d -> %s%n", i, count, f);

            Map<String, Object> cap = new LinkedHashMap<>();
            cap.put("file", f.getFileName().toString());
            cap.put("time", TS.format(now));
            if (withTop) {
                Path t = captureTop(pid, outDir, i);
                if (t != null) {
                    tops.add(t);
                    cap.put("topFile", t.getFileName().toString());
                }
            }
            manifestCaptures.add(cap);

            if (i < count) Thread.sleep(interval.toMillis());
        }

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("host", hostname());
        manifest.put("pid", pid);
        manifest.put("jvmVersion", jvmBanner != null ? jvmBanner : "unknown");
        manifest.put("strategy", winner.name());
        manifest.put("captures", manifestCaptures);
        Path mf = outDir.resolve("manifest.json");
        Files.writeString(mf, Json.write(manifest), StandardCharsets.UTF_8);
        return new CaptureResult(dumps, tops, mf, winner.name());
    }

    /** Strips jcmd's leading "pid:" line and guarantees the parser-visible timestamp line. */
    public static String normalize(String raw, LocalDateTime when) {
        String text = raw;
        int nl = text.indexOf('\n');
        if (nl > 0 && text.substring(0, nl).trim().matches("\\d+:")) {
            text = text.substring(nl + 1);
        }
        int end = text.indexOf('\n');
        String firstLine = (end < 0 ? text : text.substring(0, end)).trim();
        if (!firstLine.matches("\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}.*")) {
            text = TS.format(when) + "\n" + text;
        }
        return text;
    }

    private Path captureTop(long pid, Path outDir, int i) {
        try {
            Exec.Result r = exec.run(List.of("top", "-H", "-b", "-n", "1", "-p",
                    Long.toString(pid)), Duration.ofSeconds(15));
            if (r.ok() && r.stdout().contains("PID")) {
                Path t = outDir.resolve(String.format("top-%02d.txt", i));
                Files.writeString(t, r.stdout(), StandardCharsets.UTF_8);
                return t;
            }
            log.println("  (top -H unavailable on this system - skipping CPU snapshot)");
        } catch (Exception e) {
            log.println("  (top -H failed: " + e.getMessage() + " - skipping CPU snapshot)");
        }
        return null;
    }

    private static String firstBanner(String dump) {
        for (String line : dump.split("\n", 50)) {
            if (line.startsWith("Full thread dump")) return line.trim();
        }
        return null;
    }

    private static String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }
}
