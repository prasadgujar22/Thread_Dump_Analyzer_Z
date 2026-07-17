package com.tda;

import com.tda.core.model.LockRef;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HotSpotParserTest {

    @Test
    void jdk8HeaderFields() {
        ThreadDump d = Fixtures.parseOne("""
                Full thread dump Java HotSpot(TM) 64-Bit Server VM (25.202-b08 mixed mode):

                "worker" #46 daemon prio=9 os_prio=0 tid=0x00007f0a3c001000 nid=0x2f03 waiting on condition [0x00007f0a778f7000]
                   java.lang.Thread.State: TIMED_WAITING (parking)
                \tat sun.misc.Unsafe.park(Native Method)
                """);
        ThreadInfo t = d.threads().get(0);
        assertEquals("worker", t.name());
        assertEquals(46L, t.javaId());
        assertTrue(t.isDaemon());
        assertEquals(9, t.priority());
        assertEquals(0, t.osPriority());
        assertEquals("0x00007f0a3c001000", t.tidHex());
        assertEquals("0x2f03", t.nidHex());
        assertEquals(0x2f03, t.nidDecimal());
        assertNull(t.cpuMillis(), "JDK 8 headers carry no cpu= field");
        assertEquals(ThreadState.TIMED_WAITING, t.state());
        assertEquals("TIMED_WAITING (parking)", t.stateDetail());
        assertEquals("waiting on condition", t.headerCondition());
        assertTrue(t.frames().get(0).isNative());
    }

    @Test
    void jdk11PlusHeaderHasCpuAndElapsed() {
        ThreadDump d = Fixtures.parseOne("""
                "main" #1 prio=5 os_prio=0 cpu=141.51ms elapsed=64.68s tid=0x00007f6bd8028fd0 nid=0x2f03 waiting on condition  [0x00007f6bdf6f9000]
                   java.lang.Thread.State: TIMED_WAITING (sleeping)
                \tat java.lang.Thread.sleep(java.base@17.0.11/Native Method)
                """);
        ThreadInfo t = d.threads().get(0);
        assertEquals(141.51, t.cpuMillis(), 0.001);
        assertEquals(64.68, t.elapsedSeconds(), 0.001);
        // module prefix "java.base@17.0.11/" is stripped from frame signatures
        assertEquals("java.lang.Thread.sleep", t.frames().get(0).signature());
    }

    @Test
    void jdk21HeaderWithDecimalNidAndOsTid() {
        ThreadDump d = Fixtures.parseOne("""
                "main" #1 [12314] prio=5 os_prio=0 cpu=20.44ms elapsed=0.15s tid=0x00007f0d18028fd0 nid=12314 runnable [0x00007f0d1f6f9000]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.A.b(A.java:1)
                """);
        ThreadInfo t = d.threads().get(0);
        assertEquals(12314, t.nidDecimal());
        assertEquals("0x301a", t.nidHex());
        assertEquals(ThreadState.RUNNABLE, t.state());
    }

    @Test
    void vmThreadsWithoutJavaStacksAreKept() {
        ThreadDump d = Fixtures.parseOne("""
                "VM Thread" os_prio=0 tid=0x00007f0a300c8000 nid=0x2ed3 runnable

                "GC task thread#0 (ParallelGC)" os_prio=0 tid=0x00007f0a3001e800 nid=0x2ec4 runnable
                """);
        assertEquals(2, d.threads().size());
        assertTrue(d.threads().get(0).isVmThread());
        assertNull(d.threads().get(0).javaId());
        assertEquals(0, d.javaThreads().size());
    }

    @Test
    void lockAnnotationsAllKinds() {
        ThreadDump d = Fixtures.parseOne("""
                "t" #9 prio=5 os_prio=0 tid=0x00007f0000000001 nid=0x10 waiting for monitor entry [0x00007f0000000002]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat com.acme.A.a(A.java:1)
                \t- waiting to lock <0x00000000d0000001> (a com.acme.L1)
                \tat com.acme.A.b(A.java:2)
                \t- locked <0x00000000d0000002> (a com.acme.L2)
                \t- eliminated <owner is scalar replaced> (a com.acme.L3)
                \tat com.acme.A.c(A.java:3)
                \t- parking to wait for  <0x00000000d0000004> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)

                   Locked ownable synchronizers:
                \t- <0x00000000d0000005> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
                """);
        ThreadInfo t = d.threads().get(0);
        List<LockRef> locks = t.locks();
        assertEquals(5, locks.size());
        assertEquals(LockRef.Kind.WAITING_TO_LOCK, locks.get(0).kind());
        assertEquals("0x00000000d0000001", locks.get(0).address());
        assertEquals("com.acme.L1", locks.get(0).className());
        assertEquals(LockRef.Kind.LOCKED_MONITOR, locks.get(1).kind());
        assertEquals(LockRef.Kind.ELIMINATED, locks.get(2).kind());
        assertNull(locks.get(2).address());
        assertEquals(LockRef.Kind.PARKING_TO_WAIT_FOR, locks.get(3).kind());
        assertEquals(LockRef.Kind.LOCKED_SYNCHRONIZER, locks.get(4).kind());
        assertEquals("java.util.concurrent.locks.ReentrantLock$NonfairSync", locks.get(4).className());
    }

    @Test
    void synchronizersAttachToThePrecedingThread() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("healthy_jdk8.txt"));
        ThreadInfo pool = d.findByName("pool-2-thread-1");
        assertNotNull(pool);
        assertEquals(1, pool.heldLocks().size());
        assertEquals(LockRef.Kind.LOCKED_SYNCHRONIZER, pool.heldLocks().get(0).kind());
    }

    @Test
    void jvmDeadlockReportParsed() {
        ThreadDump d = Fixtures.parseOne(Fixtures.read("deadlock_jdk8.txt"));
        assertEquals(1, d.jvmDeadlockCycles().size());
        assertEquals(List.of("OrderWriter-1", "LedgerFlush-1"), d.jvmDeadlockCycles().get(0));
        // the repeated stacks inside the deadlock report must not create phantom threads
        assertEquals(5, d.threads().size());
    }

    @Test
    void healthyFixturesParseCleanly() {
        ThreadDump d8 = Fixtures.parseOne(Fixtures.read("healthy_jdk8.txt"));
        assertEquals(8, d8.javaThreads().size());
        assertEquals(4, d8.threads().size() - d8.javaThreads().size(), "4 VM threads");
        ThreadDump d17 = Fixtures.parseOne(Fixtures.read("healthy_jdk17.txt"));
        assertEquals(6, d17.javaThreads().size());
        assertTrue(d17.issues().isEmpty(), "SMR section must not be reported as noise: " + d17.issues());
    }

    @Test
    void weblogicStuckMarkerSurvivesInName() {
        ThreadDump d = Fixtures.parseAll(Fixtures.read("stuck_series_weblogic.log")).get(2);
        assertTrue(d.threads().stream().anyMatch(t -> t.name().startsWith("[STUCK] ExecuteThread")));
    }

    @Test
    void unrecognizedLinesAreReportedNotFatal() {
        ThreadDump d = Fixtures.parseOne("""
                Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                "w" #12 daemon prio=5 os_prio=0 cpu=1.0ms elapsed=9.0s tid=0x00007f0000001000 nid=0x100 runnable  [0x00007f0000100000]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.Worker.spin(Worker.java:10)
                SOME GARBAGE LINE
                \tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)
                """);
        assertEquals(1, d.threads().size());
        assertEquals(2, d.threads().get(0).frames().size());
        assertFalse(d.issues().isEmpty());
        assertTrue(d.issues().get(0).message().contains("SOME GARBAGE LINE"));
    }
}
