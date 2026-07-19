package com.tda.capture;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Command-runner abstraction (real + fake for tests). */
public interface Exec {

    record Result(int exitCode, String stdout, String stderr) {
        public boolean ok() { return exitCode == 0; }
    }

    Result run(List<String> command, Duration timeout) throws IOException, InterruptedException;

    static Exec system() {
        return (command, timeout) -> {
            Process p = new ProcessBuilder(command).start();
            // read output concurrently so a chatty process can't fill the pipe and stall
            var stdout = new java.io.ByteArrayOutputStream();
            var stderr = new java.io.ByteArrayOutputStream();
            Thread outT = new Thread(() -> {
                try { p.getInputStream().transferTo(stdout); } catch (IOException ignored) { }
            });
            Thread errT = new Thread(() -> {
                try { p.getErrorStream().transferTo(stderr); } catch (IOException ignored) { }
            });
            outT.setDaemon(true);
            errT.setDaemon(true);
            outT.start();
            errT.start();
            if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                return new Result(-1, "", "timed out after " + timeout);
            }
            outT.join(2000);
            errT.join(2000);
            return new Result(p.exitValue(),
                    stdout.toString(StandardCharsets.UTF_8), stderr.toString(StandardCharsets.UTF_8));
        };
    }
}
