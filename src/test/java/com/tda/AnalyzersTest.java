package com.tda;

import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.analysis.single.StackDeduplicator;
import com.tda.core.analysis.single.StateDistribution;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadState;
import com.tda.core.model.TopHSample;
import com.tda.core.parse.TopHParser;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalyzersTest {

    @Test
    void stateDistributionCountsJavaThreadsOnly() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("healthy_jdk8.txt"));
        StateDistribution.Result r = new StateDistribution().analyze(d);
        assertEquals(8, r.total());
        assertEquals(4, r.vmThreads());
        assertEquals(2, r.counts().get(ThreadState.RUNNABLE));
        assertEquals(4, r.counts().get(ThreadState.WAITING));
        assertEquals(25.0, r.percent(ThreadState.RUNNABLE), 0.01);
    }

    @Test
    void lockGraphCoversMonitorsAndKnowsWaitReleasesThem() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("deadlock_jdk8.txt"));
        LockGraph g = LockGraph.build(d);
        // OrderWriter-1 holds the OrderBook monitor; LedgerFlush-1 and WaitingWriter-2 wait for it
        assertEquals("OrderWriter-1", g.holderOf("0x00000000d70158c0").name());
        assertEquals("LedgerFlush-1", g.waitsFor().get("OrderWriter-1"));
        assertEquals("OrderWriter-1", g.waitsFor().get("LedgerFlush-1"));
        assertEquals("OrderWriter-1", g.waitsFor().get("WaitingWriter-2"));
        // a thread inside Object.wait() must NOT count as holding the monitor it released
        ThreadDump healthy = Fixtures.parseOne(Fixtures.read("healthy_jdk8.txt"));
        LockGraph hg = LockGraph.build(healthy);
        assertNull(hg.holderOf("0x00000000e0008e98"), "Finalizer released its queue lock in wait()");
    }

    @Test
    void transitiveVictimsCountChains() {
        // A holds L1 (B waits); B holds L2 (C, D wait) -> A transitively starves 3
        ThreadDump d = Fixtures.parseOne("""
                "A" #1 prio=5 os_prio=0 tid=0x0000000000000001 nid=0x1 runnable [0x0000000000000101]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.A.work(A.java:1)
                \t- locked <0x00000000000000a1> (a com.acme.L1)

                "B" #2 prio=5 os_prio=0 tid=0x0000000000000002 nid=0x2 waiting for monitor entry [0x0000000000000102]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat com.acme.B.work(B.java:1)
                \t- waiting to lock <0x00000000000000a1> (a com.acme.L1)
                \t- locked <0x00000000000000a2> (a com.acme.L2)

                "C" #3 prio=5 os_prio=0 tid=0x0000000000000003 nid=0x3 waiting for monitor entry [0x0000000000000103]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat com.acme.C.work(C.java:1)
                \t- waiting to lock <0x00000000000000a2> (a com.acme.L2)

                "D" #4 prio=5 os_prio=0 tid=0x0000000000000004 nid=0x4 waiting for monitor entry [0x0000000000000104]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat com.acme.D.work(D.java:1)
                \t- waiting to lock <0x00000000000000a2> (a com.acme.L2)
                """);
        LockGraph g = LockGraph.build(d);
        Map<String, Integer> v = g.transitiveVictimCounts();
        assertEquals(3, v.get("A"));
        assertEquals(2, v.get("B"));
    }

    @Test
    void deadlockDetectedIndependentlyWithoutJvmReport() {
        // same deadlock fixture with the JVM's own report chopped off
        String noReport = Fixtures.read("deadlock_jdk8.txt")
                .substring(0, Fixtures.read("deadlock_jdk8.txt").indexOf("Found one Java-level deadlock"));
        ThreadDump d = Fixtures.parseOne(noReport);
        assertTrue(d.jvmDeadlockCycles().isEmpty());
        List<DeadlockDetector.Cycle> cycles = new DeadlockDetector().detect(d, LockGraph.build(d));
        assertEquals(1, cycles.size());
        assertEquals("wait-for-graph", cycles.get(0).source());
        assertTrue(cycles.get(0).threadNames().containsAll(List.of("OrderWriter-1", "LedgerFlush-1")));
    }

    @Test
    void jvmReportedAndDetectedCyclesAreDeduplicated() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("deadlock_jdk8.txt"));
        List<DeadlockDetector.Cycle> cycles = new DeadlockDetector().detect(d, LockGraph.build(d));
        assertEquals(1, cycles.size(), "same cycle from both sources must be reported once");
        assertEquals("jvm", cycles.get(0).source());
    }

    @Test
    void identicalStacksAreGrouped() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("pool_exhaustion_jdk17.txt"));
        List<StackDeduplicator.Group> groups = new StackDeduplicator().analyze(d, 10, 40);
        assertEquals(12, groups.get(0).count(), "12 identical Hikari borrow stacks");
        assertTrue(groups.get(0).frames().stream().anyMatch(f -> f.contains("ConcurrentBag.borrow")));
        assertEquals(12, groups.get(0).states().get(ThreadState.TIMED_WAITING));
    }

    @Test
    void poolGrouperKnowsTheMiddlewareZoo() {
        PoolGrouper g = new PoolGrouper();
        assertEquals("WebLogic queue 'weblogic.kernel.Default (self-tuning)'",
                g.poolOf("[STUCK] ExecuteThread: '12' for queue: 'weblogic.kernel.Default (self-tuning)'"));
        assertEquals("WebSphere WebContainer", g.poolOf("WebContainer : 7"));
        assertEquals("http-nio-8080", g.poolOf("http-nio-8080-exec-3"));
        assertEquals("WildFly 'default' workers", g.poolOf("default task-12"));
        assertEquals("ForkJoinPool.commonPool", g.poolOf("ForkJoinPool.commonPool-worker-3"));
        assertEquals("ForkJoinPool-2", g.poolOf("ForkJoinPool-2-worker-11"));
        assertEquals("pool-7", g.poolOf("pool-7-thread-12"));
        assertNull(g.poolOf("main"));
    }

    @Test
    void userPoolPatternsRunFirst() {
        PoolGrouper g = new PoolGrouper(Map.of("Batch", "^batch-(\\w+)-\\d+$"));
        assertEquals("Batch invoices", g.poolOf("batch-invoices-3"));
    }

    @Test
    void topHJoinsOnDecimalNid() {
        List<TopHSample> top = new TopHParser().parse(Fixtures.read("top_h_sample.txt"));
        assertEquals(4, top.size());
        TopHSample hot = top.stream().filter(s -> s.pid() == 12018).findFirst().orElseThrow();
        assertEquals(97.3, hot.cpuPercent(), 0.01);
        // 12018 == 0x2ef2 == pool-2-thread-1 in healthy_jdk8.txt
        ThreadDump d = Fixtures.parseOne(Fixtures.read("healthy_jdk8.txt"));
        assertEquals(12018, d.findByName("pool-2-thread-1").nidDecimal());
    }
}
