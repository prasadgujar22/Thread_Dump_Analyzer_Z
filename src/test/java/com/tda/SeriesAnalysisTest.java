package com.tda;

import com.tda.core.analysis.series.Baseline;
import com.tda.core.analysis.series.PersistentLockHolders;
import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.SeriesIndex;
import com.tda.core.analysis.series.StuckThreadDetector;
import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.model.DumpSeries;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SeriesAnalysisTest {

    private static final String STACK_A = """
               java.lang.Thread.State: RUNNABLE
            \tat java.net.SocketInputStream.socketRead0(Native Method)
            \tat com.acme.Client.call(Client.java:10)
            \tat com.acme.Worker.run(Worker.java:5)
            """;
    private static final String STACK_B = """
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.Other.compute(Other.java:99)
            \tat com.acme.Worker.run(Worker.java:5)
            """;

    private String dump(String ts, String stack, String state) {
        return ts + "\nFull thread dump Java HotSpot(TM) 64-Bit Server VM (25.202-b08 mixed mode):\n\n"
                + "\"frozen\" #7 prio=5 os_prio=0 tid=0x0000000000000007 nid=0x7 runnable [0x0000000000000107]\n"
                + stack.replace("RUNNABLE", state) + "\n";
    }

    private DumpSeries seriesOf(String... texts) {
        try {
            return new com.tda.core.parse.DumpSetLoader().loadFromStrings(
                    List.of("s"), List.of(String.join("\n", texts)));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    @Test
    void unchangedFingerprintForKDumpsIsStuck() {
        DumpSeries s = seriesOf(
                dump("2026-07-13 03:00:00", STACK_A, "RUNNABLE"),
                dump("2026-07-13 03:01:00", STACK_A, "RUNNABLE"),
                dump("2026-07-13 03:02:00", STACK_A, "RUNNABLE"));
        List<StuckThreadDetector.Stuck> st =
                new StuckThreadDetector(3, 8, 40).detect(SeriesIndex.build(s));
        assertEquals(1, st.size());
        assertEquals("frozen", st.get(0).name());
        assertEquals(3, st.get(0).runLength());
        assertTrue(st.get(0).frozenFrames().get(0).contains("socketRead0"));
    }

    @Test
    void changedStackBreaksTheRun() {
        DumpSeries s = seriesOf(
                dump("2026-07-13 03:00:00", STACK_A, "RUNNABLE"),
                dump("2026-07-13 03:01:00", STACK_B, "RUNNABLE"),
                dump("2026-07-13 03:02:00", STACK_A, "RUNNABLE"));
        assertTrue(new StuckThreadDetector(3, 8, 40).detect(SeriesIndex.build(s)).isEmpty());
    }

    @Test
    void waitingThreadsAreNotStuckEvenWithFrozenStack() {
        DumpSeries s = seriesOf(
                dump("2026-07-13 03:00:00", STACK_A, "WAITING (parking)"),
                dump("2026-07-13 03:01:00", STACK_A, "WAITING (parking)"),
                dump("2026-07-13 03:02:00", STACK_A, "WAITING (parking)"));
        assertTrue(new StuckThreadDetector(3, 8, 40).detect(SeriesIndex.build(s)).isEmpty(),
                "idle pool threads parked on their queue are healthy, not stuck");
    }

    @Test
    void weblogicStatusPrefixDoesNotBreakMatching() {
        String d1 = dump("2026-07-13 03:00:00", STACK_A, "RUNNABLE")
                .replace("\"frozen\"", "\"[ACTIVE] ExecuteThread: '9' for queue: 'q'\"");
        String d2 = dump("2026-07-13 03:01:00", STACK_A, "RUNNABLE")
                .replace("\"frozen\"", "\"[STUCK] ExecuteThread: '9' for queue: 'q'\"");
        String d3 = dump("2026-07-13 03:02:00", STACK_A, "RUNNABLE")
                .replace("\"frozen\"", "\"[STUCK] ExecuteThread: '9' for queue: 'q'\"");
        DumpSeries s = seriesOf(d1, d2, d3);
        List<StuckThreadDetector.Stuck> st =
                new StuckThreadDetector(3, 8, 40).detect(SeriesIndex.build(s));
        assertEquals(1, st.size(), "[ACTIVE] -> [STUCK] rename must not lose the match");
        assertEquals("ExecuteThread: '9' for queue: 'q'", st.get(0).name());
    }

    @Test
    void persistentLockHolderAccumulatesStarvedThreads() {
        DumpSeries s = Fixtures.series("stuck_series_weblogic.log");
        List<PersistentLockHolders.Holder> holders = new PersistentLockHolders().detect(s, 2);
        assertEquals(1, holders.size());
        PersistentLockHolders.Holder h = holders.get(0);
        assertEquals("org.apache.log4j.spi.RootLogger", h.lockClass());
        assertTrue(h.holderName().contains("ExecuteThread: '4'"));
        assertEquals(List.of(0, 1, 2, 3, 4), h.dumps());
        assertEquals(6, h.starvedTotal(), "cumulative distinct waiters across the series");
    }

    @Test
    void monotonicPoolGrowthIsALeakSuspect() {
        DumpSeries s = Fixtures.series("stuck_series_weblogic.log");
        List<PoolTrend.Trend> trends = new PoolTrend().analyze(s, new PoolGrouper(), 5);
        PoolTrend.Trend leak = trends.stream()
                .filter(t -> t.pool().equals("pool-9")).findFirst().orElseThrow();
        assertTrue(leak.leakSuspect());
        assertEquals(List.of(3, 5, 7, 9, 11), leak.counts());
        PoolTrend.Trend wl = trends.stream()
                .filter(t -> t.pool().startsWith("WebLogic")).findFirst().orElseThrow();
        assertFalse(wl.leakSuspect(), "growth below threshold must not be flagged");
    }

    @Test
    void baselineDiffFlagsNewRecurringStacks() {
        Baseline b = new Baseline();
        PoolGrouper pools = new PoolGrouper();
        Map<String, Object> baseline = b.build(Fixtures.series("healthy_jdk17.txt"), pools, 15);
        assertEquals("tda-baseline", baseline.get("type"));
        Map<String, Object> diff = b.diff(Fixtures.series("pool_exhaustion_jdk17.txt"),
                pools, 15, baseline);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> news = (List<Map<String, Object>>) diff.get("newRecurringStacks");
        assertTrue(news.stream().anyMatch(n -> n.get("frames").toString().contains("HikariPool.getConnection")),
                "the Hikari borrow stack is new relative to the healthy baseline");
    }
}
