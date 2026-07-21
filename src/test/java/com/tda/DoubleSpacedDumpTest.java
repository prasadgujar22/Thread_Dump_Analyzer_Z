package com.tda;

import com.tda.core.model.LockRef;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dumps that pass through Windows consoles / log shippers often arrive "double-spaced" -
 * a blank line between every line. Blank lines must not terminate a thread block eagerly:
 * before this regression suite, such dumps parsed as N headers with zero states/frames
 * (states={UNKNOWN=N}, everything else "unrecognized").
 */
class DoubleSpacedDumpTest {

    /** Inserts a blank line after every line, like the real-world broken dumps. */
    private static String doubleSpace(String text) {
        return text.replace("\n", "\n\n");
    }

    private static final String DUMP = """
            2026-07-21 08:45:11
            Full thread dump Java HotSpot(TM) 64-Bit Server VM (25.491-b10 mixed mode):

            "OkHttp prod-jaeger-6-otlp.obs.example.com" #1377 daemon prio=5 os_prio=0 tid=0x00007fd9d8018800 nid=0x1f787b runnable [0x00007fd86a578000]
               java.lang.Thread.State: RUNNABLE
            \tat java.net.SocketInputStream.socketRead0(Native Method)
            \tat java.net.SocketInputStream.socketRead(SocketInputStream.java:116)
            \tat sun.security.ssl.SSLSocketImpl$AppInputStream.read(SSLSocketImpl.java:979)
            \tat okio.InputStreamSource.read(JvmOkio.kt:93)
            \tat okhttp3.internal.http2.Http2Reader.nextFrame(Http2Reader.kt:89)

            "[ACTIVE] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)'" #52 daemon prio=5 os_prio=0 tid=0x00007fd9d8019900 nid=0x1f787c waiting for monitor entry [0x00007fd86a579000]
               java.lang.Thread.State: BLOCKED (on object monitor)
            \tat com.acme.cache.CacheManager.get(CacheManager.java:55)
            \t- waiting to lock <0x00000000e0000100> (a com.acme.cache.CacheManager)
            \tat weblogic.work.ExecuteThread.execute(ExecuteThread.java:415)

            "holder" #53 daemon prio=5 os_prio=0 tid=0x00007fd9d801aa00 nid=0x1f787d runnable [0x00007fd86a57a000]
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.cache.CacheManager.refresh(CacheManager.java:88)
            \t- locked <0x00000000e0000100> (a com.acme.cache.CacheManager)
            \tat weblogic.work.ExecuteThread.execute(ExecuteThread.java:415)

               Locked ownable synchronizers:
            \t- <0x00000000e0000200> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)

            "VM Thread" os_prio=0 tid=0x00007fd9d80c8000 nid=0x1f7800 runnable

            JNI global refs: 233, weak refs: 100
            """;

    @Test
    void doubleSpacedDumpParsesLikeTheOriginal() {
        ThreadDump normal = Fixtures.parseOne(DUMP);
        ThreadDump spaced = Fixtures.parseOne(doubleSpace(DUMP));

        assertEquals(normal.threads().size(), spaced.threads().size());
        for (int i = 0; i < normal.threads().size(); i++) {
            ThreadInfo a = normal.threads().get(i);
            ThreadInfo b = spaced.threads().get(i);
            assertEquals(a.name(), b.name());
            assertEquals(a.state(), b.state(), a.name() + " state");
            assertEquals(a.frames().size(), b.frames().size(), a.name() + " frames");
            assertEquals(a.locks().size(), b.locks().size(), a.name() + " locks");
        }

        ThreadInfo okhttp = spaced.findByName("OkHttp prod-jaeger-6-otlp.obs.example.com");
        assertEquals(ThreadState.RUNNABLE, okhttp.state());
        assertEquals(5, okhttp.frames().size());
        assertEquals("java.net.SocketInputStream.socketRead0", okhttp.frames().get(0).signature());

        ThreadInfo blocked = spaced.findByName(
                "[ACTIVE] ExecuteThread: '4' for queue: 'weblogic.kernel.Default (self-tuning)'");
        assertEquals(ThreadState.BLOCKED, blocked.state());
        assertNotNull(blocked.waitingOnLock());
        assertEquals("0x00000000e0000100", blocked.waitingOnLock().address());

        // the synchronizers section (separated by blanks) still attaches to "holder"
        ThreadInfo holder = spaced.findByName("holder");
        assertTrue(holder.locks().stream().anyMatch(l ->
                l.kind() == LockRef.Kind.LOCKED_SYNCHRONIZER
                        && "0x00000000e0000200".equals(l.address())));

        // and nothing was skipped
        assertTrue(spaced.issues().isEmpty(),
                "no unrecognized lines expected, got: " + spaced.issues());
    }

    @Test
    void doubleSpacedDeadlockReportStillYieldsTheCycle() {
        ThreadDump spaced = Fixtures.parseOne(doubleSpace(Fixtures.read("deadlock_jdk8.txt")));
        ThreadDump normal = Fixtures.parseOne(Fixtures.read("deadlock_jdk8.txt"));
        assertEquals(normal.jvmDeadlockCycles(), spaced.jvmDeadlockCycles());
        assertEquals(normal.threads().size(), spaced.threads().size());
    }

    @Test
    void everyFixtureSurvivesDoubleSpacing() {
        for (String fixture : List.of("healthy_jdk8.txt", "healthy_jdk17.txt",
                "pool_exhaustion_jdk17.txt", "spinning_jdk17.log", "stuck_series_weblogic.log")) {
            String text = Fixtures.read(fixture);
            List<ThreadDump> normal = Fixtures.parseAll(text);
            List<ThreadDump> spaced = Fixtures.parseAll(doubleSpace(text));
            assertEquals(normal.size(), spaced.size(), fixture + ": dump count");
            for (int i = 0; i < normal.size(); i++) {
                assertEquals(normal.get(i).threads().size(), spaced.get(i).threads().size(),
                        fixture + " dump " + i + ": thread count");
                for (int t = 0; t < normal.get(i).threads().size(); t++) {
                    ThreadInfo a = normal.get(i).threads().get(t);
                    ThreadInfo b = spaced.get(i).threads().get(t);
                    assertEquals(a.state(), b.state(), fixture + ": " + a.name());
                    assertEquals(a.frames().size(), b.frames().size(), fixture + ": " + a.name());
                }
            }
        }
    }

    @Test
    void logLinesAfterABlankStillCannotPolluteTheLastThread() {
        ThreadDump d = Fixtures.parseOne("""
                "worker" #10 daemon prio=5 os_prio=0 tid=0x00007fd9d8018800 nid=0x1001 runnable [0x00007fd86a578000]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.Worker.run(Worker.java:10)

                SEVERE: request failed
                \tat com.acme.Boom.explode(Boom.java:1)
                """);
        ThreadInfo worker = d.findByName("worker");
        assertEquals(1, worker.frames().size(),
                "the logged exception frame must not be appended to the thread");
        assertEquals("com.acme.Worker.run", worker.frames().get(0).signature());
    }
}
