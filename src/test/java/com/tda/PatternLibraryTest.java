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
        assertEquals("CRITICAL", byId(fs, "stuck-thread").get("severity"));
        assertEquals("CRITICAL", byId(fs, "network-hang").get("severity"));
        byId(fs, "sync-logging-bottleneck");
        byId(fs, "top-blocker");
        Map<String, Object> leak = byId(fs, "thread-leak");
        assertTrue(String.valueOf(leak.get("title")).contains("pool-9"));
    }

    @Test
    void healthyDumpsProduceNoFindings() {
        assertTrue(findings("healthy_jdk8.txt").isEmpty(),
                "a healthy dump must not cry wolf");
        assertTrue(findings("healthy_jdk17.txt").isEmpty());
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
