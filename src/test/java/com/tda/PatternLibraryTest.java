package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every detector exercised end-to-end through the engine against its incident fixture. */
class PatternLibraryTest {

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> findings(String fixture) {
        Map<String, Object> result = new AnalysisEngine(new AnalysisOptions())
                .analyze(Fixtures.series(fixture), List.of());
        return (List<Map<String, Object>>) (List<?>) result.get("findings");
    }

    private Map<String, Object> byId(List<Map<String, Object>> fs, String id) {
        return fs.stream().filter(f -> id.equals(f.get("id"))).findFirst()
                .orElseThrow(() -> new AssertionError("missing finding " + id + " in "
                        + fs.stream().map(f -> f.get("id")).toList()));
    }

    @Test
    void deadlockIsAlwaysCritical() {
        Map<String, Object> f = byId(findings("deadlock_jdk8.txt"), "deadlock");
        assertEquals("CRITICAL", f.get("severity"));
        assertTrue(String.valueOf(f.get("detail")).contains("OrderWriter-1"));
        assertTrue(String.valueOf(f.get("recommendation")).contains("lock ordering"));
    }

    @Test
    void poolExhaustionDetectedWithRecommendation() {
        List<Map<String, Object>> fs = findings("pool_exhaustion_jdk17.txt");
        Map<String, Object> f = byId(fs, "connection-pool-exhaustion");
        assertEquals("CRITICAL", f.get("severity"), "12 waiters is critical");
        assertTrue(String.valueOf(f.get("recommendation")).contains("leak detection"));
        byId(fs, "network-hang"); // the 3 socketRead0 connection holders
    }

    @Test
    void weblogicSeriesLightsUpTheExpectedDetectors() {
        List<Map<String, Object>> fs = findings("stuck_series_weblogic.log");
        assertEquals("CRITICAL", byId(fs, "weblogic-stuck").get("severity"));
        // the log4j convoy: blocked chains behind ExecuteThread '4' (6 waiters >= 5) are CRITICAL
        assertTrue(fs.stream().anyMatch(f -> "stuck-thread".equals(f.get("id"))
                        && "CRITICAL".equals(f.get("severity"))
                        && String.valueOf(f.get("title")).contains("blocked on the same monitor")),
                "blocked-chain stuck findings must be CRITICAL with 6 victims");
        // network-hang stays CRITICAL because the frozen socket-read thread is [STUCK]-marked
        assertEquals("CRITICAL", byId(fs, "network-hang").get("severity"));
        assertEquals("CRITICAL", byId(fs, "top-blocker").get("severity"));
        byId(fs, "sync-logging-bottleneck");
        Map<String, Object> leak = byId(fs, "thread-leak");
        assertTrue(String.valueOf(leak.get("title")).contains("pool-9"));
        // every finding carries the Rule-5 evidence block
        for (Map<String, Object> f : fs) {
            if ("weblogic-hogging".equals(f.get("id"))) continue;
            Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
            assertTrue(ev.containsKey("confidence"), f.get("id") + " missing confidence");
        }
    }

    @Test
    void healthyDumpsProduceNoFindings() {
        assertTrue(findings("healthy_jdk8.txt").isEmpty(),
                "a healthy dump must not cry wolf");
        assertTrue(findings("healthy_jdk17.txt").isEmpty());
    }

    @Test
    void exceptionProcessingDetected() throws Exception {
        StringBuilder sb = new StringBuilder("""
                2026-07-16 19:00:00
                Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                """);
        for (int n = 1; n <= 6; n++) {
            sb.append(String.format("""
                    "http-nio-8080-exec-%d" #%d daemon prio=5 os_prio=0 cpu=9.00ms elapsed=50.00s tid=0x00000000000a%d000 nid=0x9%d0 runnable  [0x00000000000b%d000]
                       java.lang.Thread.State: RUNNABLE
                    \tat java.lang.Throwable.fillInStackTrace(java.base@17.0.11/Native Method)
                    \tat java.lang.Throwable.<init>(java.base@17.0.11/Throwable.java:271)
                    \tat com.acme.retry.RetryLoop.attempt(RetryLoop.java:77)
                    \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)

                       Locked ownable synchronizers:
                    \t- None

                    """, n, 40 + n, n, n, n));
        }
        var series = new com.tda.core.parse.DumpSetLoader()
                .loadFromStrings(List.of("x"), List.of(sb.toString()));
        var result = new AnalysisEngine(new AnalysisOptions()).analyze(series, List.of());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fs = (List<Map<String, Object>>) (List<?>) result.get("findings");
        Map<String, Object> f = byId(fs, "exception-processing");
        assertEquals("WARNING", f.get("severity"), "6 threads mid-exception is a throw storm");
    }

    @Test
    void findingsAreSortedBySeverity() {
        List<Map<String, Object>> fs = findings("stuck_series_weblogic.log");
        int lastRank = 0;
        for (Map<String, Object> f : fs) {
            int rank = switch (String.valueOf(f.get("severity"))) {
                case "CRITICAL" -> 0;
                case "WARNING" -> 1;
                default -> 2;
            };
            assertTrue(rank >= lastRank, "findings must be ranked most severe first");
            lastRank = rank;
        }
    }
}
