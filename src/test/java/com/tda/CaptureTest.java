package com.tda;

import com.tda.capture.CaptureSession;
import com.tda.capture.CaptureStrategy;
import com.tda.capture.Exec;
import com.tda.capture.ProcFs;
import com.tda.capture.Strategies;
import com.tda.capture.WatchLoop;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CaptureTest {

    private static final String FAKE_DUMP = """
            Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

            "main" #1 prio=5 os_prio=0 cpu=1.0ms elapsed=1.0s tid=0x0000000000000001 nid=0x1 runnable [0x0000000000000101]
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.A.b(A.java:1)
            """;

    /** Fake ProcFs whose values tests can set directly. */
    static final class FakeProc implements ProcFs {
        Path exe;
        Long ticks;
        Integer threads;
        int cores = 4;
        @Override public boolean isSupported() { return true; }
        @Override public Optional<Path> exePath(long pid) { return Optional.ofNullable(exe); }
        @Override public OptionalLong cpuTicks(long pid) {
            return ticks == null ? OptionalLong.empty() : OptionalLong.of(ticks);
        }
        @Override public OptionalInt threadCount(long pid) {
            return threads == null ? OptionalInt.empty() : OptionalInt.of(threads);
        }
        @Override public int cpuCores() { return cores; }
    }

    /** Fake Exec recording invocations and returning canned results per command name. */
    static final class FakeExec implements Exec {
        final List<List<String>> calls = new ArrayList<>();
        String jcmdOut = FAKE_DUMP;
        int jcmdExit = 0;
        @Override public Result run(List<String> command, Duration timeout) {
            calls.add(command);
            String bin = Path.of(command.get(0)).getFileName().toString();
            if (bin.equals("jcmd")) return new Result(jcmdExit, jcmdOut, "");
            if (bin.equals("top")) return new Result(0, "   PID USER %CPU %MEM COMMAND\n  99 x 1.0 2.0 java\n", "");
            if (bin.equals("kill")) return new Result(0, "", "");
            return new Result(127, "", "not found");
        }
    }

    @Test
    void targetJdkStrategyResolvesJcmdNextToTheTargetsJavaBinary(@TempDir Path tmp) throws Exception {
        Path bin = tmp.resolve("jdk8/bin");
        Files.createDirectories(bin);
        Files.writeString(bin.resolve("java"), "#!/bin/sh\n");
        Files.writeString(bin.resolve("jcmd"), "#!/bin/sh\n");
        bin.resolve("jcmd").toFile().setExecutable(true);
        FakeProc proc = new FakeProc();
        proc.exe = bin.resolve("java");
        FakeExec exec = new FakeExec();

        CaptureStrategy s = Strategies.targetJdkJcmd(proc, exec);
        Optional<String> out = s.tryCapture(1234);
        assertTrue(out.isPresent());
        assertEquals(bin.resolve("jcmd").toString(), exec.calls.get(0).get(0),
                "must exec the TARGET JDK's jcmd, not our own");
        assertEquals(List.of("1234", "Thread.print", "-l"), exec.calls.get(0).subList(1, 4));
    }

    @Test
    void strategyChainFallsThroughWhenTargetHasNoJcmd(@TempDir Path tmp) throws Exception {
        FakeProc proc = new FakeProc();          // no exe -> strategy 1 unavailable
        FakeExec exec = new FakeExec();
        CaptureSession session = new CaptureSession(List.of(
                Strategies.targetJdkJcmd(proc, exec),
                // stand-in for own-jdk jcmd that succeeds:
                new CaptureStrategy() {
                    @Override public String name() { return "fake-own-jcmd"; }
                    @Override public Optional<String> tryCapture(long pid) { return Optional.of(FAKE_DUMP); }
                }), exec, new PrintStream(java.io.OutputStream.nullOutputStream()));
        CaptureSession.CaptureResult r = session.run(42, 2, Duration.ofMillis(10), tmp, false);
        assertEquals("fake-own-jcmd", r.strategy());
        assertEquals(2, r.dumpFiles().size());
        // files are analysis-ready: first line is the timestamp the parser reads
        String first = Files.readAllLines(r.dumpFiles().get(0)).get(0);
        assertTrue(first.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}"), first);
        assertTrue(Files.readString(r.manifest()).contains("\"strategy\":\"fake-own-jcmd\""));
    }

    @Test
    void jcmdPidPrefixLineIsStripped() {
        String normalized = CaptureSession.normalize("4242:\n" + FAKE_DUMP,
                LocalDateTime.of(2026, 7, 17, 12, 0, 0));
        assertTrue(normalized.startsWith("2026-07-17 12:00:00\nFull thread dump"));
    }

    @Test
    void watchTriggersOnCpuAndHonorsCooldown() throws Exception {
        FakeProc proc = new FakeProc();
        proc.cores = 1;
        AtomicLong clock = new AtomicLong(0);
        List<String> fired = new ArrayList<>();
        WatchLoop loop = new WatchLoop(proc, new PrintStream(java.io.OutputStream.nullOutputStream()),
                clock::get);

        proc.ticks = 1000L;
        assertNull(loop.poll(1, 90.0, null, Duration.ofSeconds(60), fired::add),
                "first poll only establishes the baseline");
        // 5 seconds later the process consumed 480 ticks = 4.8s cpu = 96% of one core
        clock.set(5_000_000_000L);
        proc.ticks = 1480L;
        assertNotNull(loop.poll(1, 90.0, null, Duration.ofSeconds(60), fired::add));
        assertEquals(1, fired.size());
        assertTrue(fired.get(0).contains("cpu 96"), fired.get(0));
        // still breaching 5s later, but inside the cooldown window -> suppressed
        clock.set(10_000_000_000L);
        proc.ticks = 1960L;
        assertNull(loop.poll(1, 90.0, null, Duration.ofSeconds(60), fired::add));
        assertEquals(1, fired.size());
    }

    @Test
    void watchTriggersOnThreadCount() throws Exception {
        FakeProc proc = new FakeProc();
        proc.threads = 900;
        List<String> fired = new ArrayList<>();
        WatchLoop loop = new WatchLoop(proc, new PrintStream(java.io.OutputStream.nullOutputStream()),
                () -> 0L);
        assertNotNull(loop.poll(1, null, 800, Duration.ofMinutes(10), fired::add));
        assertTrue(fired.get(0).contains("thread count 900 >= threshold 800"));
    }

    @Test
    void integrationCaptureFromChildJvm(@TempDir Path tmp) throws Exception {
        // spawn a real child JVM and capture from it through the real strategy chain
        Path javaBin = Path.of(System.getProperty("java.home"), "bin", "java");
        Process child = new ProcessBuilder(javaBin.toString(),
                "-cp", System.getProperty("java.class.path"),
                CaptureTest.class.getName() + "$Sleeper").start();
        try {
            Thread.sleep(1500); // let it reach main
            CaptureSession session = CaptureSession.standard(
                    ProcFs.system(), Exec.system(), null,
                    new PrintStream(java.io.OutputStream.nullOutputStream()));
            CaptureSession.CaptureResult r = session.run(child.pid(), 2,
                    Duration.ofMillis(300), tmp, false);
            assertEquals(2, r.dumpFiles().size());
            var series = new com.tda.core.parse.DumpSetLoader().load(r.dumpFiles());
            assertEquals(2, series.size(), "captured files must be analysis-ready");
            assertTrue(series.get(0).threads().stream().anyMatch(t -> t.name().equals("main")));
        } finally {
            child.destroyForcibly();
        }
    }

    /** Child-JVM main: just stay alive until killed. */
    public static final class Sleeper {
        public static void main(String[] args) throws InterruptedException {
            Thread.sleep(60_000);
        }
    }
}
