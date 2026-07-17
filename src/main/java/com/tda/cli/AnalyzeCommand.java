package com.tda.cli;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.json.Json;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.TopHSample;
import com.tda.core.parse.DumpSetLoader;
import com.tda.core.parse.TopHParser;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "analyze", mixinStandardHelpOptions = true,
        description = "Analyze one thread dump or an ordered series (files may each contain several dumps).")
public class AnalyzeCommand implements Callable<Integer> {

    @Parameters(arity = "1..*", paramLabel = "<files>",
            description = "Dump files: raw jstack/jcmd output or server logs with embedded kill -3 dumps.")
    List<Path> files;

    @Option(names = "--json", paramLabel = "<file>", description = "Write the full analysis as JSON.")
    Path jsonOut;

    @Option(names = "--top", paramLabel = "<file>",
            description = "top -H output captured alongside the dumps; joined on nid for per-thread CPU.")
    Path topFile;

    @Option(names = "--stuck-k", paramLabel = "<n>", defaultValue = "3",
            description = "Consecutive dumps with an unchanged stack fingerprint before a thread is flagged stuck (default: ${DEFAULT-VALUE}).")
    int stuckK;

    @Option(names = "--fingerprint-depth", paramLabel = "<n>", defaultValue = "8",
            description = "Top stack frames hashed into the cross-dump fingerprint (default: ${DEFAULT-VALUE}).")
    int fingerprintDepth;

    @Option(names = "--top-stacks", paramLabel = "<n>", defaultValue = "15",
            description = "Recurring-stack groups reported per dump (default: ${DEFAULT-VALUE}).")
    int topStacks;

    @Option(names = "--pool-pattern", paramLabel = "<name=regex>",
            description = "Extra thread-pool naming rule, repeatable. Regex group 1, when present, is appended to the pool name.")
    List<String> poolPatterns;

    @Override
    public Integer call() throws Exception {
        AnalysisOptions opts = buildOptions();
        DumpSeries series = new DumpSetLoader().load(files);
        if (series.size() == 0) {
            System.err.println("No thread dumps found in the given file(s).");
            return 2;
        }
        List<TopHSample> topH = topFile != null
                ? new TopHParser().parse(Files.readString(topFile, StandardCharsets.UTF_8))
                : List.of();

        Map<String, Object> result = new AnalysisEngine(opts).analyze(series, topH);

        if (jsonOut != null) {
            Files.writeString(jsonOut, Json.write(result), StandardCharsets.UTF_8);
            System.out.println("JSON written to " + jsonOut);
        }
        printSummary(series, result);
        return 0;
    }

    AnalysisOptions buildOptions() {
        AnalysisOptions opts = new AnalysisOptions();
        opts.stuckK = stuckK;
        opts.fingerprintDepth = fingerprintDepth;
        opts.topStacks = topStacks;
        if (poolPatterns != null) {
            for (String p : poolPatterns) {
                int eq = p.indexOf('=');
                if (eq <= 0) throw new IllegalArgumentException("--pool-pattern needs name=regex, got: " + p);
                opts.poolPatterns.put(p.substring(0, eq), p.substring(eq + 1));
            }
        }
        return opts;
    }

    @SuppressWarnings("unchecked")
    private void printSummary(DumpSeries series, Map<String, Object> result) {
        System.out.printf("Parsed %d dump(s):%n", series.size());
        List<Map<String, Object>> dumps = (List<Map<String, Object>>) (List<?>) (List<Object>) result.get("dumps");
        for (Map<String, Object> d : dumps) {
            System.out.printf("  [%s] %s  threads=%s  states=%s%n",
                    d.get("index"), d.get("timestamp") != null ? d.get("timestamp") : d.get("source"),
                    d.get("totalThreads"), d.get("states"));
            List<?> deadlocks = (List<?>) d.get("deadlocks");
            if (!deadlocks.isEmpty()) {
                System.out.printf("      !! %d deadlock(s) detected%n", deadlocks.size());
            }
            List<?> issues = (List<?>) d.get("issues");
            for (Object i : issues) System.out.println("      parse note: " + i);
        }
        for (ThreadDump d : series.dumps()) {
            long stuckMarked = d.threads().stream()
                    .filter(t -> com.tda.core.analysis.single.PoolGrouper.isStuckMarked(t.name())).count();
            if (stuckMarked > 0) {
                System.out.printf("  dump %d: %d WebLogic [STUCK]/[HOGGING] thread(s)%n",
                        d.indexInSeries(), stuckMarked);
            }
        }
    }
}
