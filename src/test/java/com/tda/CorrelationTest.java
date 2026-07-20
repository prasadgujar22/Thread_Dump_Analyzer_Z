package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadInfo;
import com.tda.core.parse.DumpSetLoader;
import com.tda.core.parse.GcLogParser;
import com.tda.core.parse.JfrLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase B: GC/safepoint overlay, JFR ingestion, JDK 21 JSON dumps with virtual threads. */
class CorrelationTest {

    // ---------------------------------------------------------------- GC log parsing

    @Test
    void unifiedLoggingPausesParsed() throws Exception {
        List<GcLogParser.PauseWindow> p = new GcLogParser().parse(
                new BufferedReader(new StringReader(Fixtures.read("gc_unified.log"))));
        assertEquals(4, p.size(), p.toString());
        GcLogParser.PauseWindow full = p.stream()
                .filter(w -> w.cause().equals("System.gc()")).findFirst().orElseThrow();
        assertEquals(6250.0, full.durationMs(), 0.01);
        assertEquals("gc", full.kind());
        assertEquals(Instant.parse("2026-07-16T16:00:19.500Z"), full.start());
        GcLogParser.PauseWindow sp = p.stream()
                .filter(w -> w.kind().equals("safepoint")).findFirst().orElseThrow();
        assertEquals("G1CollectForAllocation", sp.cause());
        assertEquals(1512.214, sp.durationMs(), 0.01);
    }

    @Test
    void jdk8GcLogParsed() throws Exception {
        List<GcLogParser.PauseWindow> p = new GcLogParser().parse(
                new BufferedReader(new StringReader(Fixtures.read("gc_jdk8.log"))));
        assertEquals(3, p.size(), p.toString());
        assertEquals("Allocation Failure", p.get(0).cause());
        assertEquals(23.1456, p.get(0).durationMs(), 0.01);
        assertEquals("Metadata GC Threshold", p.get(1).cause());
        assertEquals(4512.3456, p.get(1).durationMs(), 0.01);
        assertEquals("safepoint", p.get(2).kind());
        assertEquals(123.4567, p.get(2).durationMs(), 0.01);
    }

    // ------------------------------------------------- reattribution: pause covers the dumps

    @Test
    @SuppressWarnings("unchecked")
    void frozenThreadInsideGcPauseIsReattributed() throws Exception {
        // three dumps, 2 s apart, thread frozen on app frames (would be a WARNING via 3c);
        // one giant pause covers all three dump instants
        String stack = """
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.recon.MatchEngine.scanBucket(MatchEngine.java:214)
                \tat com.acme.recon.ReconcilerLoop.run(ReconcilerLoop.java:63)
                """;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            sb.append("2026-07-16 16:20:0").append(i * 2).append("\n")
              .append("Full thread dump Java HotSpot(TM) 64-Bit Server VM (25.202-b08 mixed mode):\n\n")
              .append("\"worker\" #9 prio=5 os_prio=0 tid=0x0000000000000009 nid=0x9 runnable [0x0000000000000109]\n")
              .append(stack).append("\n");
        }
        DumpSeries s = new DumpSetLoader().loadFromStrings(List.of("x"), List.of(sb.toString()));
        var noGc = new AnalysisEngine(new AnalysisOptions()).analyze(s, List.of());
        assertTrue(((List<?>) noGc.get("findings")).stream().anyMatch(f ->
                        "stuck-thread".equals(((Map<String, Object>) f).get("id"))),
                "without GC info the frozen thread is a finding");

        // 10 s pause starting just before the first dump covers every dump instant
        var pause = List.of(new GcLogParser.PauseWindow(
                Instant.parse("2026-07-16T16:19:59Z"), 10_000, "Full GC", "gc"));
        var withGc = new AnalysisEngine(new AnalysisOptions()).analyze(s, List.of(), null, pause);
        assertTrue(((List<?>) withGc.get("findings")).stream().noneMatch(f ->
                        "stuck-thread".equals(((Map<String, Object>) f).get("id"))),
                "the same observation inside a pause window is the pause's fault");
        Map<String, Object> series = (Map<String, Object>) withGc.get("series");
        assertEquals(List.of("worker"), series.get("reattributedToGc"));
        // and the long-pause finding fires instead, CRITICAL because > 5 s
        assertTrue(((List<?>) withGc.get("findings")).stream().anyMatch(f ->
                "long-gc-pause".equals(((Map<String, Object>) f).get("id"))
                        && "CRITICAL".equals(((Map<String, Object>) f).get("severity"))));
    }

    // ---------------------------------------------------------------- JFR ingestion

    @Test
    void jfrRecordingBecomesSyntheticDumpSeries(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("test.jfr");
        try (jdk.jfr.Recording r = new jdk.jfr.Recording()) {
            r.enable("jdk.ExecutionSample").withPeriod(Duration.ofMillis(5));
            r.start();
            // burn CPU so the sampler has something to sample
            Thread burner = new Thread(() -> {
                long x = 0;
                while (!Thread.currentThread().isInterrupted()) x += System.nanoTime() % 7;
            }, "burner-thread");
            burner.setDaemon(true);
            burner.start();
            Thread.sleep(1500);
            burner.interrupt();
            r.stop();
            r.dump(file);
        }
        assertTrue(JfrLoader.looksLikeJfr(file));
        JfrLoader.JfrResult result = new JfrLoader().load(file, Duration.ofMillis(300));
        assertTrue(result.executionSamples() > 0, "sampler must have produced events");
        assertTrue(result.series().size() >= 2,
                "1.5s of samples in 300ms slices must produce a multi-dump series, got "
                        + result.series().size());
        assertTrue(result.series().get(0).threads().stream()
                        .anyMatch(t -> t.name().equals("burner-thread")),
                "the busy thread must appear in the synthetic dumps");
        // and the ordinary engine consumes it without special cases
        var analysis = new AnalysisEngine(new AnalysisOptions()).analyze(result.series(), List.of());
        assertNotNull(analysis.get("findings"));
    }

    // ------------------------------------------------- JDK 21 JSON dumps / virtual threads

    @Test
    @SuppressWarnings("unchecked")
    void jsonDumpParsesVirtualThreadsAndCarriers() throws Exception {
        DumpSeries s = new DumpSetLoader().loadFromStrings(
                List.of("vt.json"), List.of(Fixtures.read("vthreads_jdk21.json")));
        assertEquals(1, s.size());
        List<ThreadInfo> virtuals = s.get(0).threads().stream()
                .filter(ThreadInfo::isVirtual).toList();
        assertEquals(4, virtuals.size());
        assertEquals("virtual-31", virtuals.get(0).name(), "unnamed virtual threads get tid names");
        assertEquals("24", virtuals.get(0).carrierTid());
        assertEquals("main", s.get(0).findByName("main").name());

        Map<String, Object> result = new AnalysisEngine(new AnalysisOptions()).analyze(s, List.of());
        Map<String, Object> d0 = (Map<String, Object>) ((List<?>) result.get("dumps")).get(0);
        assertEquals(4, d0.get("virtualThreads"));
        assertEquals(3, d0.get("platformThreads"));
        List<Map<String, Object>> carriers = (List<Map<String, Object>>) (List<?>) d0.get("carriers");
        assertNotNull(carriers, "carrier mapping must be present");
        Map<String, Object> c24 = carriers.stream()
                .filter(c -> "24".equals(c.get("carrierTid"))).findFirst().orElseThrow();
        assertEquals("ForkJoinPool-1-worker-1", c24.get("carrier"));
        assertEquals(2, c24.get("count"), "carrier 24 runs virtual threads 31 and 32");
        // parked vs runnable virtual threads land in the ordinary state distribution
        Map<String, Object> states = (Map<String, Object>) d0.get("states");
        assertEquals(4, states.get("RUNNABLE"), "1 platform-runnable... plus v31, v33 runnable + 2 FJ workers");
    }
}
