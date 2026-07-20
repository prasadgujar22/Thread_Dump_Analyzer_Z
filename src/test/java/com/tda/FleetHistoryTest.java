package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.ClusterAnalyzer;
import com.tda.core.model.DumpSeries;
import com.tda.history.HistoryStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase D: cluster outlier scoring, H2 incident memory, release drift. */
class FleetHistoryTest {

    // ---------------------------------------------------------------- cluster mode

    @Test
    @SuppressWarnings("unchecked")
    void seededOutlierNodeIsExplained() {
        // two healthy nodes + one node with the 6-thread blocked chain
        Map<String, DumpSeries> nodes = new LinkedHashMap<>();
        nodes.put("node1", Fixtures.series("healthy_jdk17.txt"));
        nodes.put("node2", Fixtures.series("healthy_jdk17.txt"));
        nodes.put("node7", Fixtures.series("blocked_chain_jdk17.log"));
        Map<String, Object> cluster = new ClusterAnalyzer(
                new AnalysisEngine(new AnalysisOptions())).analyze(nodes);

        List<Map<String, Object>> outliers = (List<Map<String, Object>>) (List<?>) cluster.get("outliers");
        assertTrue(outliers.stream().allMatch(o -> "node7".equals(o.get("node"))),
                "only the seeded node may be flagged: " + outliers);
        assertTrue(outliers.stream().anyMatch(o ->
                        String.valueOf(o.get("explanation")).matches(
                                "node node7 diverges: \\d+% of threads BLOCKED \\(fleet median: 0%\\)")),
                "the state-divergence explanation must be a checkable sentence: " + outliers);
        assertTrue(outliers.stream().anyMatch(o -> "unique-stack".equals(o.get("kind"))
                        && String.valueOf(o.get("explanation")).contains("no other node shows")),
                "the unique blocked stack must be called out: " + outliers);

        List<Map<String, Object>> nodeRows = (List<Map<String, Object>>) (List<?>) cluster.get("nodes");
        assertEquals(3, nodeRows.size());
        assertNotNull(nodeRows.get(0).get("statePercent"));
    }

    @Test
    void uniformFleetHasNoOutliers() {
        Map<String, DumpSeries> nodes = new LinkedHashMap<>();
        nodes.put("a", Fixtures.series("healthy_jdk17.txt"));
        nodes.put("b", Fixtures.series("healthy_jdk17.txt"));
        nodes.put("c", Fixtures.series("healthy_jdk17.txt"));
        Map<String, Object> cluster = new ClusterAnalyzer(
                new AnalysisEngine(new AnalysisOptions())).analyze(nodes);
        assertEquals(List.of(), cluster.get("outliers"));
    }

    // ---------------------------------------------------------------- incident memory

    @Test
    void similarIncidentsFoundByStackOverlap(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("history.db");
        try (HistoryStore store = new HistoryStore(db)) {
            store.record("release-41", Set.of("aaa", "bbb", "ccc", "ddd"),
                    Map.of("severities", Map.of("CRITICAL", 1)), null);
            store.record("unrelated", Set.of("zzz", "yyy"),
                    Map.of("severities", Map.of()), null);

            var similar = store.similar(Set.of("aaa", "bbb", "ccc", "eee"),
                    HistoryStore.SIMILARITY_THRESHOLD);
            assertEquals(1, similar.size(), "only the overlapping incident qualifies");
            assertEquals("release-41", similar.get(0).label());
            assertEquals(0.6, similar.get(0).overlap(), 0.001, "3 shared / 5 union");
            assertTrue(similar.get(0).sharedHashes().containsAll(List.of("aaa", "bbb", "ccc")));

            assertEquals(2, store.list(10).size());
            assertEquals(1, store.search("release-41").size());
            assertNotNull(store.show(similar.get(0).id()));
        }
        assertTrue(Files.exists(tmp.resolve("history.mv.db")),
                "H2 file created at the given path (a user-supplied .db suffix is normalized)");
    }

    @Test
    void noHistoryFlagLeavesNoDatabase(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("never.db");
        // the CLI guards the store behind --no-history; verify at the CLI level
        int exit = new picocli.CommandLine(new com.tda.cli.Main()).execute(
                "analyze", "src/test/resources/fixtures/healthy_jdk17.txt",
                "--no-history", "--history-db", db.toString());
        assertEquals(0, exit);
        assertTrue(Files.list(tmp).findAny().isEmpty(), "--no-history must not create any db file");
    }

    // ---------------------------------------------------------------- release drift

    @Test
    void compareAgainstLabeledBaselineShowsDrift(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("history.db");
        Path json = tmp.resolve("drift.json");
        // 1) store the healthy build under a label
        int exit = new picocli.CommandLine(new com.tda.cli.Main()).execute(
                "analyze", "src/test/resources/fixtures/healthy_jdk17.txt",
                "--label", "build-2026.07.1", "--history-db", db.toString());
        assertEquals(0, exit);
        // 2) compare the incident dumps against that label
        exit = new picocli.CommandLine(new com.tda.cli.Main()).execute(
                "compare", "--baseline-label", "build-2026.07.1",
                "--history-db", db.toString(),
                "src/test/resources/fixtures/pool_exhaustion_jdk17.txt",
                "--json", json.toString());
        assertEquals(0, exit);
        String out = Files.readString(json);
        assertTrue(out.contains("baselineDiff"), "compare must produce the baseline-diff section");
        assertTrue(out.contains("HikariPool.getConnection"),
                "the Hikari stack is new since the labeled build");
    }
}
