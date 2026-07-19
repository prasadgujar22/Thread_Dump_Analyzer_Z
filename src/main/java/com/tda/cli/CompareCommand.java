package com.tda.cli;

import com.tda.history.HistoryStore;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * Release drift: compare the given dumps against the baseline stored by an earlier
 * {@code analyze --label <build>} run - "what changed after the deployment".
 */
@Command(name = "compare", mixinStandardHelpOptions = true,
        description = "Diff a dump series against the baseline stored under a --label in the "
                + "local history: new recurring stacks, state shifts, pool deltas since that build.")
public class CompareCommand implements Callable<Integer> {

    @Option(names = {"--baseline-label", "--baseline"}, required = true, paramLabel = "<label>",
            description = "The label given to the reference analysis (analyze --label <build>).")
    String label;

    @Option(names = "--history-db", paramLabel = "<path>",
            description = "History database location (default: ~/.tda/history.db).")
    Path historyDb;

    @Parameters(arity = "1..*", paramLabel = "<dumps...>")
    List<Path> dumps;

    @Option(names = "--json", paramLabel = "<file>")
    Path jsonOut;

    @Option(names = "--html", paramLabel = "<file>")
    Path htmlOut;

    @Override
    public Integer call() throws Exception {
        Map<String, Object> baseline;
        try (HistoryStore store = new HistoryStore(
                historyDb != null ? historyDb : HistoryStore.defaultPath())) {
            baseline = store.baselineForLabel(label);
        }
        if (baseline == null) {
            System.err.println("No stored baseline for label \"" + label
                    + "\". Run `tda analyze --label " + label + " <healthy dumps>` first.");
            return 2;
        }
        Path tmp = Files.createTempFile("tda-baseline", ".json");
        try {
            Files.writeString(tmp, com.tda.core.json.Json.write(baseline), StandardCharsets.UTF_8);
            List<String> args = new ArrayList<>();
            args.add("analyze");
            dumps.forEach(d -> args.add(d.toString()));
            args.add("--baseline");
            args.add(tmp.toString());
            args.add("--no-history"); // a comparison run should not pollute the memory
            if (jsonOut != null) { args.add("--json"); args.add(jsonOut.toString()); }
            if (htmlOut != null) { args.add("--html"); args.add(htmlOut.toString()); }
            System.out.println("Comparing against baseline \"" + label + "\" from history:");
            return new CommandLine(new Main()).execute(args.toArray(new String[0]));
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
