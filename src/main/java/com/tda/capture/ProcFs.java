package com.tda.capture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.stream.Stream;

/**
 * Thin readable interface over /proc so capture and watch logic is unit-testable with a
 * faked filesystem. Linux-only by nature; {@link #isSupported()} gates the callers.
 */
public interface ProcFs {

    boolean isSupported();

    /** Resolved /proc/&lt;pid&gt;/exe target (the JVM binary the target process runs). */
    Optional<Path> exePath(long pid);

    /** utime+stime clock ticks from /proc/&lt;pid&gt;/stat. */
    OptionalLong cpuTicks(long pid);

    /** Thread count = entry count of /proc/&lt;pid&gt;/task. */
    OptionalInt threadCount(long pid);

    int cpuCores();

    /** Kernel clock ticks per second (USER_HZ); effectively always 100 on Linux. */
    default long ticksPerSecond() { return 100; }

    /** The real /proc. */
    static ProcFs system() {
        return new ProcFs() {
            @Override public boolean isSupported() {
                return Files.isDirectory(Path.of("/proc/self"));
            }

            @Override public Optional<Path> exePath(long pid) {
                try {
                    return Optional.of(Files.readSymbolicLink(Path.of("/proc/" + pid + "/exe")));
                } catch (IOException | UnsupportedOperationException e) {
                    return Optional.empty();
                }
            }

            @Override public OptionalLong cpuTicks(long pid) {
                try {
                    String stat = Files.readString(Path.of("/proc/" + pid + "/stat"));
                    // fields after the parenthesized comm (which may contain spaces)
                    int close = stat.lastIndexOf(')');
                    String[] f = stat.substring(close + 2).split(" ");
                    // post-comm indices: 0=state ... 11=utime 12=stime
                    return OptionalLong.of(Long.parseLong(f[11]) + Long.parseLong(f[12]));
                } catch (Exception e) {
                    return OptionalLong.empty();
                }
            }

            @Override public OptionalInt threadCount(long pid) {
                try (Stream<Path> s = Files.list(Path.of("/proc/" + pid + "/task"))) {
                    return OptionalInt.of((int) s.count());
                } catch (IOException e) {
                    return OptionalInt.empty();
                }
            }

            @Override public int cpuCores() {
                return Runtime.getRuntime().availableProcessors();
            }
        };
    }
}
