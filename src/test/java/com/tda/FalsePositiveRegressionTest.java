package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.classify.IdlePatterns;
import com.tda.core.model.DumpSeries;
import com.tda.core.parse.DumpSetLoader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression suite for the iteration-2 detection rules: the idle-Tomcat false positives
 * must stay dead, while the true positives (spinning threads, blocked chains) keep firing.
 */
class FalsePositiveRegressionTest {

    @SuppressWarnings("unchecked")
    private Map<String, Object> analyze(DumpSeries series) {
        return new AnalysisEngine(new AnalysisOptions()).analyze(series, List.of());
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> findings(Map<String, Object> result) {
        return (List<Map<String, Object>>) (List<?>) result.get("findings");
    }

    private DumpSeries tomcatSeries() throws IOException {
        // the fixture lives at the repo-root path the bug report names, not on the classpath
        Path dir = Path.of("fixtures/idle-tomcat-jdk21");
        DumpSetLoader loader = new DumpSetLoader();
        return loader.load(List.of(dir.resolve("TD1.txt"), dir.resolve("TD2.txt"), dir.resolve("TD3.txt")));
    }

    // ---- fixture 1: the reported bug - idle vanilla Tomcat on JDK 21 ----

    @Test
    @SuppressWarnings("unchecked")
    void idleTomcatJdk21ProducesZeroCriticalAndZeroWarning() throws IOException {
        Map<String, Object> result = analyze(tomcatSeries());
        List<Map<String, Object>> fs = findings(result);
        for (Map<String, Object> f : fs) {
            String sev = String.valueOf(f.get("severity"));
            assertTrue("INFO".equals(sev),
                    "idle Tomcat must produce no CRITICAL/WARNING, got: " + f.get("severity")
                            + " " + f.get("id") + " - " + f.get("title"));
        }
        // and the swimlane must not flag anything as stuck
        Map<String, Object> series = (Map<String, Object>) result.get("series");
        assertEquals(List.of(), series.get("stuckThreads"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void idleTomcatThreadsAreClassified() throws IOException {
        Map<String, Object> result = analyze(tomcatSeries());
        List<Map<String, Object>> threads = (List<Map<String, Object>>)
                (List<?>) ((Map<String, Object>) ((List<?>) result.get("dumps")).get(0)).get("threads");
        Map<String, Object> main = row(threads, "main");
        assertEquals("idle (acceptor/await loop)", main.get("class"),
                "Tomcat's shutdown-listener accept loop is idle by design");
        assertEquals("housekeeping", row(threads, "Reference Handler").get("class"),
                "Reference Handler's native wait is JVM housekeeping");
        assertEquals("idle (selector/poller wait)", row(threads, "http-nio-8080-Poller").get("class"));
        assertEquals("idle (waiting for work)", row(threads, "http-nio-8080-exec-1").get("class"),
                "executor take() buried under managedBlock wrappers still matches");
    }

    private Map<String, Object> row(List<Map<String, Object>> threads, String name) {
        return threads.stream().filter(t -> name.equals(t.get("name"))).findFirst()
                .orElseThrow(() -> new AssertionError("thread not found: " + name));
    }

    // ---- fixture 4a: JDK 8 variant (no cpu= fields) must also stay quiet ----

    @Test
    void idleTomcatJdk8VariantProducesNoFindings() {
        List<Map<String, Object>> fs = findings(analyze(Fixtures.series("idle_tomcat_jdk8.log")));
        assertTrue(fs.isEmpty(), "JDK 8 fallback must not flag idle-pattern threads: " + fs);
    }

    // ---- fixture 2: true positive - spinning thread with cpu advancing ~ wall clock ----

    @Test
    void spinningThreadStillFires() {
        List<Map<String, Object>> fs = findings(analyze(Fixtures.series("spinning_jdk17.log")));
        Map<String, Object> f = fs.stream().filter(x -> "stuck-thread".equals(x.get("id")))
                .findFirst().orElseThrow(() -> new AssertionError("spinning finding missing: " + fs));
        assertTrue(String.valueOf(f.get("title")).contains("Spinning"));
        Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
        assertEquals("high", ev.get("confidence"));
        assertNotNull(ev.get("cpuDeltaMillis"), "cpu-delta evidence must be attached");
        assertNotNull(ev.get("whyNotFalsePositive"));
    }

    @Test
    void spinningThreadJdk8FallbackFiresOnAppFrames() {
        List<Map<String, Object>> fs = findings(analyze(Fixtures.series("spinning_jdk8.log")));
        Map<String, Object> f = fs.stream().filter(x -> "stuck-thread".equals(x.get("id")))
                .findFirst().orElseThrow(() -> new AssertionError("JDK 8 fallback finding missing"));
        assertEquals("WARNING", f.get("severity"),
                "without cpu evidence severity is capped at WARNING, confidence medium");
        assertEquals("medium", ((Map<String, Object>) f.get("evidence")).get("confidence"));
    }

    // ---- fixture 3: true positive - blocked chain with victim count ----

    @Test
    void blockedChainIsCriticalWithVictimCount() {
        List<Map<String, Object>> fs = findings(analyze(Fixtures.series("blocked_chain_jdk17.log")));
        Map<String, Object> chain = fs.stream()
                .filter(x -> "stuck-thread".equals(x.get("id")) && "CRITICAL".equals(x.get("severity")))
                .findFirst().orElseThrow(() -> new AssertionError("blocked-chain CRITICAL missing: " + fs));
        Map<String, Object> ev = (Map<String, Object>) chain.get("evidence");
        assertEquals(6.0, ((Number) ev.get("victims")).doubleValue(), 0.01,
                "victim count is the CRITICAL justification");
        // the holder itself sits in a zero-cpu socket read -> INFO native wait, not CRITICAL
        assertTrue(fs.stream().anyMatch(x -> "idle-native-wait".equals(x.get("id"))
                        && String.valueOf(x.get("title")).contains("cache-refresher")));
        // and the top blocker names the holder
        assertTrue(fs.stream().anyMatch(x -> "top-blocker".equals(x.get("id"))
                        && "CRITICAL".equals(x.get("severity"))));
    }

    // ---- rule 4: a lock held for the whole series with zero waiters is never a finding ----

    @Test
    @SuppressWarnings("unchecked")
    void uncontendedPersistentLockIsNotReported() throws IOException {
        Map<String, Object> result = analyze(tomcatSeries());
        // Tomcat main holds its StandardServer ReentrantLock in every dump, nobody waits
        Map<String, Object> series = (Map<String, Object>) result.get("series");
        assertEquals(List.of(), series.get("persistentLockHolders"));
    }

    // ---- user-extensible idle patterns ----

    @Test
    void userIdlePatternFileExtendsTheKnowledgeBase(@org.junit.jupiter.api.io.TempDir Path tmp)
            throws IOException {
        Path f = tmp.resolve("site-patterns.yaml");
        Files.writeString(f, """
                patterns:
                  - name: site-batch-idle
                    label: idle (site batch poller)
                    frames:
                      - com.acme.Client.call
                """, StandardCharsets.UTF_8);
        IdlePatterns patterns = IdlePatterns.withUserFile(f);
        // the WAITING->RUNNABLE socketRead stack from the series tests matches the site pattern now
        DumpSeries s;
        try {
            s = new DumpSetLoader().loadFromStrings(List.of("x"), List.of("""
                    2026-07-16 18:00:00
                    Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                    "site-poller" #9 prio=5 os_prio=0 cpu=1.00ms elapsed=100.00s tid=0x0000000000000009 nid=0x9 runnable [0x0000000000000109]
                       java.lang.Thread.State: RUNNABLE
                    \tat java.net.SocketInputStream.socketRead0(java.base@17.0.11/Native Method)
                    \tat com.acme.Client.call(Client.java:10)
                    \tat com.acme.Worker.run(Worker.java:5)
                    """));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        assertEquals("idle (site batch poller)", patterns.labelFor(s.get(0).threads().get(0)));
        // built-ins still present after the merge
        assertTrue(patterns.entries().stream().anyMatch(e -> "socket-accept".equals(e.name())));
    }
}
