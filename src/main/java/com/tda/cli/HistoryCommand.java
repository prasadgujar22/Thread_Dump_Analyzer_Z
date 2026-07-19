package com.tda.cli;

import com.tda.core.json.Json;
import com.tda.history.HistoryStore;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "history", mixinStandardHelpOptions = true,
        description = "Browse the local incident memory (~/.tda/history.db). The db contains "
                + "stack frames - treat it with the same sensitivity as the dumps.",
        subcommands = {HistoryCommand.HList.class, HistoryCommand.Search.class, HistoryCommand.Show.class})
public class HistoryCommand implements Runnable {

    @Override
    public void run() {
        picocli.CommandLine.usage(this, System.out);
    }

    abstract static class Base {
        @Option(names = "--history-db", paramLabel = "<path>",
                description = "History database location (default: ~/.tda/history.db).")
        Path historyDb;

        HistoryStore open() throws Exception {
            return new HistoryStore(historyDb != null ? historyDb : HistoryStore.defaultPath());
        }

        void print(List<HistoryStore.Entry> entries) {
            if (entries.isEmpty()) {
                System.out.println("(no matching analyses in history)");
                return;
            }
            System.out.printf("%-6s %-24s %-24s %s%n", "ID", "DATE", "LABEL", "FINDINGS");
            for (HistoryStore.Entry e : entries) {
                System.out.printf("%-6d %-24s %-24s %s%n", e.id(),
                        e.ts().toString().replace("T", " ").substring(0, 19),
                        e.label() != null ? e.label() : "-",
                        e.summary().getOrDefault("severities", "{}"));
            }
        }
    }

    @Command(name = "list", mixinStandardHelpOptions = true,
            description = "List stored analyses, newest first.")
    static class HList extends Base implements Callable<Integer> {
        @Option(names = "--limit", defaultValue = "25")
        int limit;

        @Override public Integer call() throws Exception {
            try (HistoryStore s = open()) {
                print(s.list(limit));
            }
            return 0;
        }
    }

    @Command(name = "search", mixinStandardHelpOptions = true,
            description = "Search stored analyses by label or findings text.")
    static class Search extends Base implements Callable<Integer> {
        @Parameters(paramLabel = "<text>")
        String text;

        @Override public Integer call() throws Exception {
            try (HistoryStore s = open()) {
                print(s.search(text));
            }
            return 0;
        }
    }

    @Command(name = "show", mixinStandardHelpOptions = true,
            description = "Show one stored analysis in full (summary JSON + stack fingerprints).")
    static class Show extends Base implements Callable<Integer> {
        @Parameters(paramLabel = "<id>")
        long id;

        @Override public Integer call() throws Exception {
            try (HistoryStore s = open()) {
                HistoryStore.Entry e = s.show(id);
                if (e == null) {
                    System.err.println("no analysis with id " + id);
                    return 2;
                }
                System.out.printf("id=%d  date=%s  label=%s%n", e.id(), e.ts(),
                        e.label() != null ? e.label() : "-");
                System.out.println(Json.write(e.summary()));
                System.out.println("stack fingerprints: " + s.stacksOf(id));
            }
            return 0;
        }
    }
}
