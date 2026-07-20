package com.tda.capture;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/** The built-in capture strategies, in fallback order. */
public final class Strategies {

    private static final Duration JCMD_TIMEOUT = Duration.ofSeconds(30);

    private Strategies() {}

    /**
     * Strategy 1: resolve the TARGET JVM's own JDK via /proc/&lt;pid&gt;/exe and exec its
     * jcmd. Using the target's own tooling sidesteps attach-protocol version mismatches
     * entirely (a JDK 8 target is dumped by JDK 8's jcmd).
     */
    public static CaptureStrategy targetJdkJcmd(ProcFs proc, Exec exec) {
        return new CaptureStrategy() {
            @Override public String name() { return "target-jdk-jcmd"; }

            @Override public Optional<String> tryCapture(long pid) {
                Optional<Path> exe = proc.exePath(pid);
                if (exe.isEmpty()) return Optional.empty();
                Path bin = exe.get().getParent();          // .../jdk/bin/java -> .../jdk/bin
                if (bin == null) return Optional.empty();
                Path jcmd = bin.resolve("jcmd");
                if (!Files.isExecutable(jcmd)) {
                    // JRE layout: <jdk>/jre/bin/java - hop up to the JDK's bin
                    Path up = bin.getParent() != null ? bin.getParent().getParent() : null;
                    jcmd = up != null ? up.resolve("bin/jcmd") : null;
                    if (jcmd == null || !Files.isExecutable(jcmd)) return Optional.empty();
                }
                return runJcmd(exec, jcmd, pid);
            }
        };
    }

    /** Strategy 1b: our own runtime's jcmd (works for same-era targets). */
    public static CaptureStrategy ownJdkJcmd(Exec exec) {
        return new CaptureStrategy() {
            @Override public String name() { return "own-jdk-jcmd"; }

            @Override public Optional<String> tryCapture(long pid) {
                Path jcmd = Path.of(System.getProperty("java.home"), "bin", "jcmd");
                if (!Files.isExecutable(jcmd)) return Optional.empty();
                return runJcmd(exec, jcmd, pid);
            }
        };
    }

    private static Optional<String> runJcmd(Exec exec, Path jcmd, long pid) {
        try {
            Exec.Result r = exec.run(List.of(jcmd.toString(), Long.toString(pid),
                    "Thread.print", "-l"), JCMD_TIMEOUT);
            if (r.ok() && r.stdout().contains("Full thread dump")) return Optional.of(r.stdout());
            return Optional.empty();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    /**
     * Strategy 2: the Attach API from our own JVM (same OS user required). Reaches
     * HotSpotVirtualMachine.remoteDataDump reflectively; the jar manifest carries
     * {@code Add-Opens: jdk.attach/sun.tools.attach} so this works under java -jar.
     * Any failure (JRE without jdk.attach, protocol mismatch, module lockdown) falls through.
     */
    public static CaptureStrategy attachApi() {
        return new CaptureStrategy() {
            @Override public String name() { return "attach-api"; }

            @Override public Optional<String> tryCapture(long pid) {
                try {
                    com.sun.tools.attach.VirtualMachine vm =
                            com.sun.tools.attach.VirtualMachine.attach(Long.toString(pid));
                    try {
                        var m = vm.getClass().getMethod("remoteDataDump", Object[].class);
                        m.setAccessible(true);
                        try (InputStream in = (InputStream) m.invoke(vm,
                                (Object) new Object[]{"-l"})) {
                            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                            return text.contains("Full thread dump")
                                    ? Optional.of(text) : Optional.empty();
                        }
                    } finally {
                        vm.detach();
                    }
                } catch (Throwable t) { // LinkageError on JREs, InaccessibleObject, IOException...
                    return Optional.empty();
                }
            }
        };
    }

    /**
     * Strategy 3 (last resort): SIGQUIT. The JVM writes the dump to ITS OWN stdout, not
     * ours - with a --stdout-log the new bytes appended to that log are captured and the
     * existing splitter digs the dump out; without one the session prints where to look.
     */
    public static CaptureStrategy sigquit(Exec exec, Path stdoutLog) {
        return new CaptureStrategy() {
            @Override public String name() { return "sigquit" + (stdoutLog != null ? "+tail" : ""); }

            @Override public Optional<String> tryCapture(long pid) {
                try {
                    long before = stdoutLog != null && Files.exists(stdoutLog)
                            ? Files.size(stdoutLog) : 0;
                    Exec.Result r = exec.run(List.of("kill", "-QUIT", Long.toString(pid)),
                            Duration.ofSeconds(5));
                    if (!r.ok()) return Optional.empty();
                    if (stdoutLog == null) return Optional.empty(); // signal sent; nothing to read
                    // give the JVM a moment to flush, then read what got appended
                    for (int i = 0; i < 20; i++) {
                        Thread.sleep(250);
                        long now = Files.exists(stdoutLog) ? Files.size(stdoutLog) : 0;
                        if (now > before) {
                            Thread.sleep(500); // let the dump finish writing
                            byte[] all = Files.readAllBytes(stdoutLog);
                            String appended = new String(all, (int) before,
                                    (int) (all.length - before), StandardCharsets.UTF_8);
                            if (appended.contains("Full thread dump")) return Optional.of(appended);
                        }
                    }
                    return Optional.empty();
                } catch (IOException | InterruptedException e) {
                    if (e instanceof InterruptedException) Thread.currentThread().interrupt();
                    return Optional.empty();
                }
            }
        };
    }
}
