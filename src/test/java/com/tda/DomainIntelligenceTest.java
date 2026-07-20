package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.classify.FrameMeanings;
import com.tda.core.analysis.pattern.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase C: frame meanings, utilization, rules DSL, pool-sizing hints. */
class DomainIntelligenceTest {

    @SuppressWarnings("unchecked")
    private Map<String, Object> analyze(String fixture) {
        return new AnalysisEngine(new AnalysisOptions()).analyze(Fixtures.series(fixture), List.of());
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> findings(Map<String, Object> result) {
        return (List<Map<String, Object>>) (List<?>) result.get("findings");
    }

    // ---------------------------------------------------------------- frame meanings

    @Test
    @SuppressWarnings("unchecked")
    void threadsGetPlainEnglishActivities() {
        Map<String, Object> result = analyze("pool_exhaustion_jdk17.txt");
        Map<String, Object> d0 = (Map<String, Object>) ((List<?>) result.get("dumps")).get(0);
        List<Map<String, Object>> threads = (List<Map<String, Object>>) (List<?>) d0.get("threads");
        Map<String, Object> waiter = threads.stream()
                .filter(t -> "http-nio-8080-exec-1".equals(t.get("name"))).findFirst().orElseThrow();
        assertEquals("waiting to borrow a connection from HikariCP", waiter.get("activity"));
        assertEquals("db-pool-wait", waiter.get("category"));
        Map<String, Object> holder = threads.stream()
                .filter(t -> "http-nio-8080-exec-20".equals(t.get("name"))).findFirst().orElseThrow();
        assertEquals("db-wait", holder.get("category"), "oracle.net.ns read = waiting on Oracle");

        Map<String, Object> categories = (Map<String, Object>) d0.get("categories");
        assertEquals(12, categories.get("db-pool-wait"));
        assertEquals(3, categories.get("db-wait"));
        assertNotNull(result.get("meaningsCatalog"), "the report needs the catalog for tree annotation");
    }

    @Test
    void userMeaningsOverrideBundled(@TempDir Path tmp) throws IOException {
        Path f = tmp.resolve("site-meanings.yaml");
        Files.writeString(f, """
                meanings:
                  - name: acme-mainframe
                    category: mq-wait
                    activity: waiting on the ACME mainframe bridge
                    narrative: Site-specific MQ bridge call.
                    frames:
                      - com.acme.mainframe.MqBridge
                """);
        FrameMeanings m = FrameMeanings.withUserFile(f);
        var series = Fixtures.series("stuck_series_weblogic.log");
        var stuck = series.get(0).threads().stream()
                .filter(t -> t.name().contains("ExecuteThread: '12'")).findFirst().orElseThrow();
        assertEquals("waiting on the ACME mainframe bridge", m.meaningFor(stuck).activity());
        assertTrue(m.entries().stream().anyMatch(e -> e.name().equals("hikari-borrow")),
                "bundled entries survive the merge");
    }

    // ---------------------------------------------------------------- rules DSL

    @Test
    void bundledRulesStillProduceTheMigratedFindings() {
        // the four frame-scan built-ins now run through the DSL with the same ids
        var fs = findings(analyze("pool_exhaustion_jdk17.txt"));
        Map<String, Object> pool = fs.stream()
                .filter(f -> "connection-pool-exhaustion".equals(f.get("id"))).findFirst().orElseThrow();
        assertEquals("CRITICAL", pool.get("severity"), "12 waiters >= criticalThreads 10");
        var wl = findings(analyze("stuck_series_weblogic.log"));
        assertTrue(wl.stream().anyMatch(f -> "sync-logging-bottleneck".equals(f.get("id"))
                && "WARNING".equals(f.get("severity"))), "6 blocked < criticalThreads 10 stays WARNING");
    }

    @Test
    void customRuleFiresEndToEnd(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("site-rules.yaml");
        Files.writeString(f, """
                rules:
                  - id: acme-mq-bridge-wait
                    title: "{count} threads stuck in the ACME mainframe bridge"
                    severity: warning
                    recommendation: Check the mainframe LPAR and add a bridge read timeout.
                    match:
                      frames:
                        - com.acme.mainframe.MqBridge.call
                      states:
                        - RUNNABLE
                      minThreads: 1
                      persistDumps: 3
                """);
        List<Rule> rules = Rule.merged(List.of(f));
        var result = new AnalysisEngine(new AnalysisOptions(), null, null, rules)
                .analyze(Fixtures.series("stuck_series_weblogic.log"), List.of());
        var fs = findings(result);
        Map<String, Object> hit = fs.stream()
                .filter(x -> "acme-mq-bridge-wait".equals(x.get("id"))).findFirst().orElseThrow();
        assertEquals("WARNING", hit.get("severity"));
        assertTrue(String.valueOf(hit.get("title")).matches("\\d+ threads stuck in the ACME mainframe bridge"));
        assertEquals("high", ((Map<String, Object>) hit.get("evidence")).get("confidence"),
                "persistence-corroborated rules are high confidence");
    }

    @Test
    void ruleValidationRejectsBadSchema(@TempDir Path tmp) throws IOException {
        Path bad = tmp.resolve("bad.yaml");
        Files.writeString(bad, """
                rules:
                  - id: broken
                    title: x
                    severity: catastrophic
                    recommendation: y
                    match:
                      frames:
                        - foo
                """);
        IOException e = assertThrows(IOException.class, () -> Rule.loadFile(bad));
        assertTrue(e.getMessage().contains("severity"), e.getMessage());

        Path noMatch = tmp.resolve("nomatch.yaml");
        Files.writeString(noMatch, """
                rules:
                  - id: empty-match
                    title: x
                    severity: info
                    recommendation: y
                    match:
                      minThreads: 3
                """);
        e = assertThrows(IOException.class, () -> Rule.loadFile(noMatch));
        assertTrue(e.getMessage().contains("at least"), e.getMessage());
    }

    @Test
    void spinningCpuConditionInTheDsl(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("spin-rule.yaml");
        Files.writeString(f, """
                rules:
                  - id: site-spin
                    title: "{count} reconciler thread(s) burning CPU"
                    severity: warning
                    recommendation: Profile MatchEngine.scanBucket.
                    match:
                      frames:
                        - com.acme.recon.MatchEngine
                      states:
                        - RUNNABLE
                      persistDumps: 3
                      cpuDelta: spinning
                """);
        var rules = Rule.merged(List.of(f));
        var result = new AnalysisEngine(new AnalysisOptions(), null, null, rules)
                .analyze(Fixtures.series("spinning_jdk17.log"), List.of());
        assertTrue(findings(result).stream().anyMatch(x -> "site-spin".equals(x.get("id"))),
                "cpuDelta: spinning must corroborate against cpu= fields");
        // the same rule against the JDK 8 series (no cpu=) must NOT fire
        var result8 = new AnalysisEngine(new AnalysisOptions(), null, null, rules)
                .analyze(Fixtures.series("spinning_jdk8.log"), List.of());
        assertTrue(findings(result8).stream().noneMatch(x -> "site-spin".equals(x.get("id"))),
                "a cpu condition without cpu data cannot hold");
    }

    // ------------------------------------------------- utilization + sizing hints

    @Test
    @SuppressWarnings("unchecked")
    void poolsCarryBusyIdleUtilization() {
        Map<String, Object> result = analyze("stuck_series_weblogic.log");
        Map<String, Object> d0 = (Map<String, Object>) ((List<?>) result.get("dumps")).get(0);
        List<Map<String, Object>> pools = (List<Map<String, Object>>) (List<?>) d0.get("pools");
        Map<String, Object> wl = pools.stream()
                .filter(p -> String.valueOf(p.get("pool")).startsWith("WebLogic")).findFirst().orElseThrow();
        assertTrue((Integer) wl.get("idle") >= 3,
                "the STANDBY waitForRequest threads classify idle: " + wl);
        assertTrue((Integer) wl.get("busy") >= 4, "the stuck/blocked/logger threads are busy: " + wl);
    }

    @Test
    void busyPoolWithBlockedWorkGetsAnIncreaseHintAtInfoOnly() {
        var fs = findings(analyze("blocked_chain_jdk17.log"));
        Map<String, Object> hint = fs.stream()
                .filter(f -> "pool-sizing".equals(f.get("id"))).findFirst().orElseThrow();
        assertEquals("INFO", hint.get("severity"), "sizing hints must never exceed INFO");
        assertTrue(String.valueOf(hint.get("title")).contains("consider increasing"));
    }
}
