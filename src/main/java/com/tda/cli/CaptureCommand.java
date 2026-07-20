package com.tda.cli;

import com.tda.capture.CaptureSession;
import com.tda.capture.Exec;
import com.tda.capture.ProcFs;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "capture", mixinStandardHelpOptions = true,
        description = "Capture an analysis-ready dump series from a live JVM. Strategy chain: "
                + "the target JVM's own jcmd (cross-version safe), our JDK's jcmd, the Attach API, "
                + "then SIGQUIT (+ --stdout-log tailing).")
public class CaptureCommand implements Callable<Integer> {

    @Option(names = "--pid", required = true, description = "Target JVM process id.")
    long pid;

    @Option(names = "--count", defaultValue = "5",
            description = "Dumps to capture (default: ${DEFAULT-VALUE}).")
    int count;

    @Option(names = "--interval", defaultValue = "10s",
            description = "Delay between captures, e.g. 10s, 1m (default: ${DEFAULT-VALUE}).")
    String interval;

    @Option(names = "--out", paramLabel = "<dir>",
            description = "Output directory (default: tda-capture-<pid>-<time>).")
    Path out;

    @Option(names = "--with-top",
            description = "Also snapshot top -H at each capture point (Linux; joined on nid in analysis).")
    boolean withTop;

    @Option(names = "--stdout-log", paramLabel = "<path>",
            description = "The target's stdout log (catalina.out, WebLogic .out); enables the SIGQUIT fallback to tail dumps out of it.")
    Path stdoutLog;

    @Option(names = "--analyze",
            description = "Run the analysis immediately after capture (writes report.html into the output dir).")
    boolean analyze;

    @Override
    public Integer call() throws Exception {
        Duration ivl = Durations.parse(interval);
        Path dir = out != null ? out : Path.of("tda-capture-" + pid + "-"
                + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").format(java.time.LocalDateTime.now()));
        CaptureSession session = CaptureSession.standard(
                ProcFs.system(), Exec.system(), stdoutLog, System.out);
        CaptureSession.CaptureResult result = session.run(pid, count, ivl, dir, withTop);

        System.out.printf("%nCaptured %d dump(s) via %s into %s%n",
                result.dumpFiles().size(), result.strategy(), dir);
        if (analyze) {
            List<String> args = new ArrayList<>();
            args.add("analyze");
            result.dumpFiles().forEach(f -> args.add(f.toString()));
            if (!result.topFiles().isEmpty()) {
                args.add("--top");
                args.add(result.topFiles().get(result.topFiles().size() - 1).toString());
            }
            args.add("--html");
            args.add(dir.resolve("report.html").toString());
            args.add("--json");
            args.add(dir.resolve("analysis.json").toString());
            return new CommandLine(new Main()).execute(args.toArray(new String[0]));
        }
        System.out.println("Analyze with:  java -jar tda.jar analyze " + dir + "/dump-*.txt"
                + (result.topFiles().isEmpty() ? "" : " --top " + result.topFiles().get(0)));
        return 0;
    }
}
