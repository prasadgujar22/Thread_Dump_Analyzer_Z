package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.parse.DumpSetLoader;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The report's per-thread stack entries must show the FULL dump content - frames
 * interleaved with lock annotations - and single-dump analyses must still carry the
 * per-thread state overview.
 */
class ReportStackDetailTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> analyze(String text) {
        try {
            var series = new DumpSetLoader().loadFromStrings(List.of("t"), List.of(text));
            return new AnalysisEngine(new AnalysisOptions()).analyze(series, List.of());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> firstDump(Map<String, Object> result) {
        return (Map<String, Object>) ((List<?>) result.get("dumps")).get(0);
    }

    @SuppressWarnings("unchecked")
    private static List<String> stackOf(Map<String, Object> dump, String threadName) {
        for (Object o : (List<?>) dump.get("threads")) {
            Map<String, Object> t = (Map<String, Object>) o;
            if (threadName.equals(t.get("name"))) {
                Object key = t.get("stack");
                assertNotNull(key, threadName + " has no stack key");
                return (List<String>) ((Map<String, Object>) dump.get("stacks")).get(key);
            }
        }
        throw new AssertionError("thread not found: " + threadName);
    }

    private static final String LOCK_DUMP = """
            2026-07-16 19:00:00
            Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

            "holder" #41 daemon prio=5 os_prio=0 tid=0x0000000000a01000 nid=0x901 runnable  [0x0000000000b01000]
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.cache.CacheManager.refresh(CacheManager.java:88)
            \t- locked <0x00000000e0000100> (a com.acme.cache.CacheManager)
            \tat com.acme.web.ReportServlet.doGet(ReportServlet.java:41)
            \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)

               Locked ownable synchronizers:
            \t- <0x00000000e0000200> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)

            "waiter-a" #42 daemon prio=5 os_prio=0 tid=0x0000000000a02000 nid=0x902 waiting for monitor entry  [0x0000000000b02000]
               java.lang.Thread.State: BLOCKED (on object monitor)
            \tat com.acme.cache.CacheManager.get(CacheManager.java:55)
            \t- waiting to lock <0x00000000e0000100> (a com.acme.cache.CacheManager)
            \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)

            "same-frames-lock-1" #43 daemon prio=5 os_prio=0 tid=0x0000000000a03000 nid=0x903 runnable  [0x0000000000b03000]
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.util.Worker.work(Worker.java:10)
            \t- locked <0x00000000e0000301> (a com.acme.util.Bucket)
            \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)

            "same-frames-lock-2" #44 daemon prio=5 os_prio=0 tid=0x0000000000a04000 nid=0x904 runnable  [0x0000000000b04000]
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.util.Worker.work(Worker.java:10)
            \t- locked <0x00000000e0000302> (a com.acme.util.Bucket)
            \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)

            """;

    @Test
    void stackEntriesInterleaveLockAnnotations() {
        Map<String, Object> d = firstDump(analyze(LOCK_DUMP));

        List<String> holder = stackOf(d, "holder");
        assertEquals("com.acme.cache.CacheManager.refresh(CacheManager.java:88)", holder.get(0));
        assertEquals("- locked <0x00000000e0000100> (a com.acme.cache.CacheManager)", holder.get(1),
                "the held-monitor annotation must follow its frame");
        assertTrue(holder.contains("Locked ownable synchronizers:"),
                "jstack -l synchronizer holds must be shown");
        assertTrue(holder.contains("- <0x00000000e0000200> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)"));

        List<String> waiter = stackOf(d, "waiter-a");
        assertEquals("- waiting to lock <0x00000000e0000100> (a com.acme.cache.CacheManager)",
                waiter.get(1));
    }

    @Test
    @SuppressWarnings("unchecked")
    void identicalFramesWithDifferentLocksDoNotShareAStackEntry() {
        Map<String, Object> d = firstDump(analyze(LOCK_DUMP));
        String k1 = null, k2 = null;
        for (Object o : (List<?>) d.get("threads")) {
            Map<String, Object> t = (Map<String, Object>) o;
            if ("same-frames-lock-1".equals(t.get("name"))) k1 = (String) t.get("stack");
            if ("same-frames-lock-2".equals(t.get("name"))) k2 = (String) t.get("stack");
        }
        assertNotEquals(k1, k2, "different lock addresses must not collapse into one entry");
        assertTrue(stackOf(d, "same-frames-lock-1").contains("- locked <0x00000000e0000301> (a com.acme.util.Bucket)"));
        assertTrue(stackOf(d, "same-frames-lock-2").contains("- locked <0x00000000e0000302> (a com.acme.util.Bucket)"));
    }

    @Test
    void javacoreStacksShowLockAnnotations() {
        Map<String, Object> result = analyze(Fixtures.read("javacore_was_jdk8.txt"));
        Map<String, Object> d = firstDump(result);
        List<String> holder = stackOf(d, "WebContainer : 1");
        assertTrue(holder.stream().anyMatch(l ->
                        l.equals("- locked <0x00000000e00a1b28> (a com.acme.cache.CacheManager)")),
                "5XESTACKTRACE entered-lock must appear inline: " + holder);
        List<String> blocked = stackOf(d, "WebContainer : 2");
        assertEquals("- waiting to lock <0x00000000e00a1b28> (a com.acme.cache.CacheManager)",
                blocked.get(1), "3XMTHREADBLOCK annotation belongs under the top frame");
    }

    @Test
    @SuppressWarnings("unchecked")
    void singleDumpStillGetsThePerThreadStateOverview() {
        Map<String, Object> result = analyze(LOCK_DUMP);
        Map<String, Object> series = (Map<String, Object>) result.get("series");
        List<Map<String, Object>> all =
                (List<Map<String, Object>>) (List<?>) series.get("allTimelines");
        assertNotNull(all, "allTimelines must exist for single dumps too");
        assertEquals(4, all.size());
        Map<String, Object> row = all.stream()
                .filter(r -> "waiter-a".equals(r.get("name"))).findFirst().orElseThrow();
        assertEquals(List.of("BLOCKED"), row.get("states"));

        Map<String, Object> dump = firstDump(result);
        Map<String, Object> states = (Map<String, Object>) dump.get("states");
        assertEquals(3, states.get("RUNNABLE"));
        assertEquals(1, states.get("BLOCKED"));
    }
}
