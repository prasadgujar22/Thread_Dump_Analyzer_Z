package com.tda.cli;

import com.tda.capture.CaptureSession;
import com.tda.capture.Exec;
import com.tda.capture.ProcFs;
import com.tda.capture.WatchLoop;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "watch", mixinStandardHelpOptions = true,
        description = "Poll a JVM's CPU%% and thread count (/proc, Linux only); auto-capture a "
                + "dump series when a threshold is breached, with a cooldown between triggers.")
public class WatchCommand implements Callable<Integer> {

    @Option(names = "--pid", required = true, description = "Target JVM process id.")
    long pid;

    @Option(names = "--cpu-threshold", paramLabel = "<pct>",
            description = "Trigger when process CPU%% (of all cores) reaches this value.")
    Double cpuThreshold;

    @Option(names = "--thread-count-threshold", paramLabel = "<n>",
            description = "Trigger when the process thread count reaches this value.")
    Integer threadThreshold;

    @Option(names = "--poll", defaultValue = "5s",
            description = "Poll interval (default: ${DEFAULT-VALUE}).")
    String poll;

    @Option(names = "--cooldown", defaultValue = "10m",
            description = "Minimum time between triggered captures (default: ${DEFAULT-VALUE}).")
    String cooldown;

    @Option(names = "--count", defaultValue = "5",
            description = "Dumps per triggered capture (default: ${DEFAULT-VALUE}).")
    int count;

    @Option(names = "--interval", defaultValue = "10s",
            description = "Delay between dumps in a triggered capture (default: ${DEFAULT-VALUE}).")
    String interval;

    @Option(names = "--out", paramLabel = "<dir>",
            description = "Base output directory; each trigger writes a timestamped subdirectory.")
    Path out;

    @Option(names = "--exec-after", paramLabel = "<cmd>",
            description = "Command to run after each triggered capture; receives the output dir as its argument.")
    String execAfter;

    @Override
    public Integer call() throws Exception {
        ProcFs proc = ProcFs.system();
        if (!proc.isSupported()) {
            System.err.println("tda watch reads /proc and is only supported on Linux. "
                    + "On other systems, schedule `tda capture` externally instead.");
            return 2;
        }
        if (cpuThreshold == null && threadThreshold == null) {
            System.err.println("Nothing to watch: give --cpu-threshold and/or --thread-count-threshold.");
            return 2;
        }
        Duration pollIvl = Durations.parse(poll);
        Duration cool = Durations.parse(cooldown);
        Duration capIvl = Durations.parse(interval);
        Path base = out != null ? out : Path.of("tda-watch-" + pid);
        Exec exec = Exec.system();

        System.out.printf("watching pid %d (poll %s, cooldown %s)%s%s - Ctrl-C to stop%n",
                pid, poll, cooldown,
                cpuThreshold != null ? String.format(", cpu>=%.0f%%", cpuThreshold) : "",
                threadThreshold != null ? ", threads>=" + threadThreshold : "");

        WatchLoop loop = new WatchLoop(proc, System.out, System::nanoTime);
        while (true) {
            loop.poll(pid, cpuThreshold, threadThreshold, cool, reason -> {
                Path dir = base.resolve("trigger-"
                        + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").format(LocalDateTime.now()));
                CaptureSession.CaptureResult r = CaptureSession
                        .standard(proc, exec, null, System.out)
                        .run(pid, count, capIvl, dir, true);
                System.out.printf("captured %d dumps -> %s (reason: %s)%n",
                        r.dumpFiles().size(), dir, reason);
                if (execAfter != null) {
                    Exec.Result er = exec.run(List.of(execAfter, dir.toString()),
                            Duration.ofMinutes(2));
                    if (!er.ok()) System.err.println("--exec-after failed: " + er.stderr());
                }
            });
            if (proc.cpuTicks(pid).isEmpty() && proc.threadCount(pid).isEmpty()) {
                System.out.println("target process " + pid + " has exited; stopping watch");
                return 0;
            }
            Thread.sleep(pollIvl.toMillis());
        }
    }
}
