package com.tda;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.LockRef;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.parse.JavacoreParser;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** IBM J9/OpenJ9 javacore format (traditional WebSphere, IBM Semeru). */
class JavacoreParserTest {

    private static ThreadDump parse(String fixture) {
        try (BufferedReader r = new BufferedReader(new StringReader(Fixtures.read(fixture)))) {
            return new JavacoreParser().parse(r, fixture);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void sniffRecognizesJavacoreHead() {
        String head = Fixtures.read("javacore_was_jdk8.txt").substring(0, 512);
        assertTrue(JavacoreParser.looksLikeJavacore(head));
        assertFalse(JavacoreParser.looksLikeJavacore(
                Fixtures.read("healthy_jdk8.txt").substring(0, 512)));
    }

    @Test
    void threadsHeaderFieldsAndStates() {
        ThreadDump d = parse("javacore_was_jdk8.txt");
        assertEquals(8, d.threads().size());

        ThreadInfo main = d.findByName("main");
        assertNotNull(main);
        assertEquals(ThreadState.WAITING, main.state());
        assertEquals(1L, main.javaId());
        assertFalse(main.isDaemon());
        assertEquals(5, main.priority());
        assertEquals("0x0000000000019100", main.tidHex());
        assertEquals(0x3039, main.nidDecimal());
        assertEquals(5234.5679, main.cpuMillis(), 0.001); // 5.234567890 secs -> ms
        assertTrue(main.stateDetail().contains("CW"));

        ThreadInfo runnable = d.findByName("WebContainer : 1");
        assertEquals(ThreadState.RUNNABLE, runnable.state());
        assertTrue(runnable.isDaemon());

        ThreadInfo blocked = d.findByName("WebContainer : 2");
        assertEquals(ThreadState.BLOCKED, blocked.state());
    }

    @Test
    void framesAreNormalizedToHotSpotShape() {
        ThreadDump d = parse("javacore_was_jdk8.txt");
        ThreadInfo t = d.findByName("WebContainer : 1");
        assertEquals("java.net.SocketInputStream.socketRead0", t.frames().get(0).signature());
        assertTrue(t.frames().get(0).isNative());
        // "(Compiled Code)" decorations are stripped from locations
        assertEquals("SocketInputStream.java:171", t.frames().get(2).location());
        // JVM banner comes from 2XMFULLTHDDUMP
        assertTrue(d.jvmBanner().contains("J9 VM"));
    }

    @Test
    void timestampAndDumpReason() {
        ThreadDump d = parse("javacore_was_jdk8.txt");
        assertNotNull(d.timestamp());
        assertTrue(d.issues().stream().anyMatch(i -> i.toString().contains("Dump Event \"user\"")));
        // LOCKS section present -> lock ownership is complete, no missing -l warning
        assertTrue(d.sawSynchronizerSection());
    }

    @Test
    void utcTimestampPreferredWhenPresent() {
        ThreadDump d = parse("javacore_deadlock.txt");
        assertEquals(Instant.parse("2026-07-12T08:15:30Z"), d.timestamp());
    }

    @Test
    void lockOwnershipFromLocksSectionAndEnteredLockAnnotations() {
        ThreadDump d = parse("javacore_was_jdk8.txt");

        ThreadInfo holder = d.findByName("WebContainer : 1");
        assertEquals(List.of("0x00000000e00a1b28"), holder.heldLockAddresses());

        ThreadInfo waiter = d.findByName("WebContainer : 2");
        LockRef w = waiter.waitingOnLock();
        assertNotNull(w);
        assertEquals(LockRef.Kind.WAITING_TO_LOCK, w.kind());
        assertEquals("0x00000000e00a1b28", w.address());
        assertEquals("com.acme.cache.CacheManager", w.className());
        // the LOCKS-section waiter entry must not duplicate the 3XMTHREADBLOCK annotation
        assertEquals(1, waiter.locks().stream()
                .filter(l -> l.kind() == LockRef.Kind.WAITING_TO_LOCK).count());

        LockGraph g = LockGraph.build(d);
        assertEquals("WebContainer : 1", g.holderOf("0x00000000e00a1b28").name());
        // most-contended first: the CacheManager monitor with two blocked entrants
        assertEquals("0x00000000e00a1b28", g.contendedLocks().get(0).address());
        assertEquals(2, g.contendedLocks().get(0).waiters().size());
    }

    @Test
    void deadlockReportAndWaitForGraphAgree() {
        ThreadDump d = parse("javacore_deadlock.txt");
        assertEquals(1, d.jvmDeadlockCycles().size());
        assertEquals(List.of("DeadLockThread 0", "DeadLockThread 1"), d.jvmDeadlockCycles().get(0));

        List<DeadlockDetector.Cycle> cycles = new DeadlockDetector().detect(d, LockGraph.build(d));
        assertEquals(1, cycles.size(), "jvm report and graph cycle dedupe to one");
        assertEquals("jvm", cycles.get(0).source());
    }

    @Test
    void loaderSniffsJavacoreAndBuildsSeries() {
        DumpSeries s = Fixtures.series("javacore_was_jdk8.txt");
        assertEquals(1, s.size());
        assertEquals(8, s.get(0).threads().size());
    }

    @Test
    void frameNormalization() {
        assertEquals("at java.lang.Thread.sleep(Native Method)",
                JavacoreParser.normalizeFrame("at java/lang/Thread.sleep(Native Method)"));
        assertEquals("at com.acme.Foo.bar(Foo.java:42)",
                JavacoreParser.normalizeFrame("at com/acme/Foo.bar(Foo.java:42(Compiled Code))"));
        assertEquals("at com.acme.Foo$Inner.baz(Foo.java:7)",
                JavacoreParser.normalizeFrame("at com/acme/Foo$Inner.baz(Foo.java:7)"));
    }
}
