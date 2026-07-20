package com.tda.cli;

import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.pattern.Finding;
import com.tda.core.analysis.pattern.PatternContext;
import com.tda.core.analysis.pattern.Rule;
import com.tda.core.analysis.pattern.RuleEngine;
import com.tda.core.analysis.series.SeriesIndex;
import com.tda.core.analysis.series.StuckClassifier;
import com.tda.core.analysis.series.StuckThreadDetector;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.parse.DumpSetLoader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "rules", mixinStandardHelpOptions = true,
        description = "Validate and dry-run site rule packs (the rules.yaml DSL).",
        subcommands = {RulesCommand.Validate.class, RulesCommand.DryRun.class})
public class RulesCommand implements Runnable {

    @Override
    public void run() {
        picocli.CommandLine.usage(this, System.out);
    }

    @Command(name = "validate", mixinStandardHelpOptions = true,
            description = "Parse a rules file and report schema errors without running anything.")
    static class Validate implements Callable<Integer> {
        @Parameters(paramLabel = "<file>")
        Path file;

        @Override
        public Integer call() {
            try {
                List<Rule> rules = Rule.loadFile(file);
                System.out.printf("%s: OK - %d rule(s)%n", file, rules.size());
                for (Rule r : rules) {
                    System.out.printf("  %-32s severity<=%s  minThreads=%d%s%s%s%n",
                            r.id(), r.severity(), r.minThreads(),
                            r.persistDumps() != null ? "  persist>=" + r.persistDumps() : "",
                            r.cpuDelta() != null ? "  cpu=" + r.cpuDelta() : "",
                            r.criticalThreads() != null ? "  critical@" + r.criticalThreads() : "");
                }
                return 0;
            } catch (Exception e) {
                System.err.println(file + ": INVALID - " + e.getMessage());
                return 2;
            }
        }
    }

    @Command(name = "dry-run", mixinStandardHelpOptions = true,
            description = "Show what a rules file would fire against the given dumps, without touching the report.")
    static class DryRun implements Callable<Integer> {
        @Parameters(index = "0", paramLabel = "<rules-file>")
        Path rulesFile;

        @Parameters(index = "1..*", paramLabel = "<dumps...>")
        List<Path> dumps;

        @Override
        public Integer call() throws Exception {
            List<Rule> rules = Rule.loadFile(rulesFile);
            DumpSeries series = new DumpSetLoader().load(dumps);
            if (series.size() == 0) {
                System.err.println("No thread dumps found in the given file(s).");
                return 3;
            }
            List<LockGraph> graphs = new ArrayList<>();
            List<List<DeadlockDetector.Cycle>> dl = new ArrayList<>();
            for (ThreadDump d : series.dumps()) {
                LockGraph g = LockGraph.build(d);
                graphs.add(g);
                dl.add(List.of());
            }
            PatternContext ctx = new PatternContext(series, graphs, dl,
                    List.<StuckClassifier.Verdict>of(), List.of(), List.of(), List.of(),
                    List.of(), com.tda.core.analysis.middleware.MiddlewareDetector.detect(series),
                    new com.tda.core.analysis.classify.ThreadClassifier(null),
                    new AnalysisOptions());
            RuleEngine engine = new RuleEngine(rules);
            int fired = 0;
            for (Rule r : rules) {
                Finding f = engine.evaluate(r, ctx);
                if (f == null) {
                    System.out.printf("  -      %-32s (no match)%n", r.id());
                } else {
                    fired++;
                    Map<String, Object> j = f.toJson();
                    System.out.printf("  FIRES  %-32s [%s] %s%n", r.id(),
                            j.get("severity"), j.get("title"));
                }
            }
            System.out.printf("%d of %d rule(s) would fire against %d dump(s)%n",
                    fired, rules.size(), series.size());
            return 0;
        }
    }
}
