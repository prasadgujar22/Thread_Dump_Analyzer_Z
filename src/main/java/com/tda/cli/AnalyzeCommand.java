package com.tda.cli;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.classify.FrameMeanings;
import com.tda.core.analysis.classify.IdlePatterns;
import com.tda.core.analysis.pattern.Rule;
import com.tda.core.json.Json;
import com.tda.core.json.JsonParser;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.TopHSample;
import com.tda.core.parse.DumpSetLoader;
import com.tda.core.parse.GcLogParser;
import com.tda.core.parse.JfrLoader;
import com.tda.core.parse.TopHParser;
import com.tda.history.HistoryStore;
import com.tda.report.HtmlReport;
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

@Command(name = "analyze", mixinStandardHelpOptions = true,
        description = "Analyze one thread dump or an ordered series (files may each contain several dumps).")
public class AnalyzeCommand implements Callable<Integer> {

    @Parameters(arity = "0..*", paramLabel = "<files>",
            description = "Dump files: raw jstack/jcmd output, server logs with embedded kill -3 "
                    + "dumps, a JDK 21+ JSON dump, or a .jfr recording.")
    List<Path> files;

    @Option(names = "--cluster", paramLabel = "<name=glob>",
            description = "Cluster mode, repeatable: analyze each node's series and compare across "
                    + "the fleet with deterministic outlier scoring (e.g. --cluster nodeA=nodeA/*.txt).")
    List<String> clusterSpecs;

    @Option(names = "--cluster-manifest", paramLabel = "<file>",
            description = "File with one name=glob line per node (alternative to repeating --cluster).")
    Path clusterManifest;

    @Option(names = "--label", paramLabel = "<build>",
            description = "Tag this analysis in the local history (release-drift tracking; see tda compare).")
    String label;

    @Option(names = "--no-history", description = "Do not record this analysis in the local history db.")
    boolean noHistory;

    @Option(names = "--history-db", paramLabel = "<path>",
            description = "History database location (default: ~/.tda/history.db). Contains stack "
                    + "frames - treat it with the same sensitivity as the dumps.")
    Path historyDb;

    @Option(names = "--fail-on", paramLabel = "critical|warning",
            description = "Exit 1 when findings at/above this severity exist (pipeline gate). "
                    + "Exit codes: 0 clean, 1 threshold met, 2 usage error, 3 parse failure.")
    String failOn;

    @Option(names = "--redact", description = "Scrub hostnames, IPs, and email-like tokens from "
            + "thread names, frames, and lock strings using deterministic pseudonyms (host-1, "
            + "ip-2) before writing the report, JSON, or webhook payload.")
    boolean redact;

    @Option(names = "--webhook", paramLabel = "<url>",
            description = "POST the findings summary to this URL after analysis. THE ONLY network "
                    + "call this tool can ever make, and only when this flag is present - "
                    + "everything else is fully offline.")
    String webhook;

    @Option(names = "--webhook-format", paramLabel = "json|slack", defaultValue = "json",
            description = "Webhook payload format: json (findings summary document) or slack "
                    + "(simple text blocks) (default: ${DEFAULT-VALUE}).")
    String webhookFormat;

    @Option(names = "--json", paramLabel = "<file>", description = "Write the full analysis as JSON.")
    Path jsonOut;

    @Option(names = "--html", paramLabel = "<file>",
            description = "Write a self-contained HTML report (charts + data inlined; works offline).")
    Path htmlOut;

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

    @Option(names = "--gc-log", paramLabel = "<file>",
            description = "GC/safepoint log(s) covering the capture window (unified logging or "
                    + "JDK 8 PrintGCDetails); pauses overlay the charts and frozen threads inside "
                    + "pauses are reattributed to GC, repeatable.")
    List<Path> gcLogs;

    @Option(names = "--jfr-slice", paramLabel = "<dur>", defaultValue = "1s",
            description = "Time slice for converting JFR execution samples into synthetic dumps (default: ${DEFAULT-VALUE}).")
    String jfrSlice;

    @Option(names = "--idle-patterns", paramLabel = "<file>",
            description = "Extra idle-pattern YAML (same format as the bundled idle-patterns.yaml); "
                    + "entries match first and same-name entries override the built-ins.")
    Path idlePatternsFile;

    @Option(names = "--frame-meanings", paramLabel = "<file>",
            description = "Extra frame-meanings YAML (what-is-this-thread-doing labels); "
                    + "same override mechanics as --idle-patterns.")
    Path frameMeaningsFile;

    @Option(names = "--rules", paramLabel = "<file>",
            description = "Site rule pack(s) on the rules.yaml DSL, repeatable; a rule with a "
                    + "bundled id overrides it. Validate first with `tda rules validate`.")
    List<Path> ruleFiles;

    @Option(names = "--critical-victims", paramLabel = "<n>", defaultValue = "5",
            description = "Threads blocked behind one holder before a finding escalates to CRITICAL (default: ${DEFAULT-VALUE}).")
    int criticalVictims;

    @Option(names = "--baseline-save", paramLabel = "<file>",
            description = "Treat this series as healthy and save a baseline document for later --baseline diffs.")
    Path baselineSave;

    @Option(names = "--baseline", paramLabel = "<file>",
            description = "Diff this (incident) series against a baseline saved with --baseline-save.")
    Path baselineIn;

    /** Filled when the input was a JFR recording; merged into the result JSON. */
    private Map<String, Object> jfrExtras;

    @Override
    public Integer call() throws Exception {
        AnalysisOptions opts = buildOptions();
        if (clusterSpecs != null || clusterManifest != null) {
            return runCluster(opts);
        }
        if (files == null || files.isEmpty()) {
            System.err.println("Give at least one dump file (or use --cluster).");
            return 2;
        }
        DumpSeries series;
        try {
            series = loadInput();
        } catch (Exception e) {
            System.err.println("parse failure: " + e.getMessage());
            return 3;
        }
        if (series.size() == 0) {
            System.err.println("No thread dumps found in the given file(s).");
            return 3;
        }
        List<TopHSample> topH = topFile != null
                ? new TopHParser().parse(Files.readString(topFile, StandardCharsets.UTF_8))
                : List.of();

        IdlePatterns idlePatterns = idlePatternsFile != null
                ? IdlePatterns.withUserFile(idlePatternsFile)
                : IdlePatterns.loadDefault();
        FrameMeanings meanings = frameMeaningsFile != null
                ? FrameMeanings.withUserFile(frameMeaningsFile)
                : FrameMeanings.loadDefault();
        List<Rule> rules = Rule.merged(ruleFiles);
        AnalysisEngine engine = new AnalysisEngine(opts, idlePatterns, meanings, rules);

        Map<String, Object> baseline = null;
        if (baselineIn != null) {
            baseline = JsonParser.parseObject(Files.readString(baselineIn, StandardCharsets.UTF_8));
            if (!"tda-baseline".equals(baseline.get("type"))) {
                System.err.println(baselineIn + " is not a tda baseline file (run --baseline-save first).");
                return 2;
            }
        }

        List<GcLogParser.PauseWindow> pauses = new ArrayList<>();
        if (gcLogs != null) {
            GcLogParser gc = new GcLogParser();
            for (Path g : gcLogs) {
                try (var r = Files.newBufferedReader(g, StandardCharsets.UTF_8)) {
                    pauses.addAll(gc.parse(r));
                }
            }
            System.out.printf("Parsed %d stop-the-world window(s) from %d GC log(s)%n",
                    pauses.size(), gcLogs.size());
        }

        Map<String, Object> result = engine.analyze(series, topH, baseline, pauses);
        if (jfrExtras != null) {
            result.putAll(jfrExtras);
            addPinnedFinding(result);
        }
        recordHistory(result, engine.buildBaseline(series));

        if (redact) {
            result = (Map<String, Object>) new com.tda.report.Redactor().redactTree(result);
        }

        if (baselineSave != null) {
            Files.writeString(baselineSave, Json.write(engine.buildBaseline(series)), StandardCharsets.UTF_8);
            System.out.println("Baseline saved to " + baselineSave);
        }
        if (jsonOut != null) {
            Files.writeString(jsonOut, Json.write(result), StandardCharsets.UTF_8);
            System.out.println("JSON written to " + jsonOut);
        }
        if (htmlOut != null) {
            String title = "Thread Dump Analysis — " + files.get(0).getFileName();
            Files.writeString(htmlOut, new HtmlReport().render(result, title), StandardCharsets.UTF_8);
            System.out.println("HTML report written to " + htmlOut);
        }
        printSummary(series, result);
        if (webhook != null) postWebhook(result);
        return exitCode(result);
    }

    /** --fail-on gate: 1 when findings at/above the threshold exist, else 0. */
    @SuppressWarnings("unchecked")
    private int exitCode(Map<String, Object> result) {
        if (failOn == null) return 0;
        boolean warnCounts = "warning".equalsIgnoreCase(failOn);
        if (!warnCounts && !"critical".equalsIgnoreCase(failOn)) {
            System.err.println("--fail-on must be critical or warning");
            return 2;
        }
        for (Map<String, Object> f : (List<Map<String, Object>>) (List<?>) result.get("findings")) {
            String sev = String.valueOf(f.get("severity"));
            if ("CRITICAL".equals(sev) || (warnCounts && "WARNING".equals(sev))) {
                System.out.printf("--fail-on %s: threshold met (%s: %s) -> exit 1%n",
                        failOn.toLowerCase(), sev, f.get("title"));
                return 1;
            }
        }
        return 0;
    }

    /** The single opt-in network action; failures warn but never fail the analysis. */
    @SuppressWarnings("unchecked")
    private void postWebhook(Map<String, Object> result) {
        try {
            List<Map<String, Object>> findings =
                    (List<Map<String, Object>>) (List<?>) result.get("findings");
            Map<String, Integer> sev = new java.util.LinkedHashMap<>();
            for (Map<String, Object> f : findings) {
                sev.merge(String.valueOf(f.get("severity")), 1, Integer::sum);
            }
            String body;
            if ("slack".equalsIgnoreCase(webhookFormat)) {
                StringBuilder text = new StringBuilder("*TDA findings*  critical: "
                        + sev.getOrDefault("CRITICAL", 0) + " · warning: "
                        + sev.getOrDefault("WARNING", 0) + " · info: "
                        + sev.getOrDefault("INFO", 0));
                findings.stream().limit(5).forEach(f ->
                        text.append("\n• [").append(f.get("severity")).append("] ")
                            .append(f.get("title")));
                body = Json.write(Map.of("text", text.toString()));
            } else {
                List<Object> top = new ArrayList<>();
                findings.stream().limit(10).forEach(f -> top.add(Map.of(
                        "severity", f.get("severity"), "id", f.get("id"), "title", f.get("title"))));
                body = Json.write(Map.of("tool", "tda", "severities", sev, "findings", top));
            }
            var client = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(10)).build();
            var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(webhook))
                    .header("Content-Type", "application/json")
                    .timeout(java.time.Duration.ofSeconds(15))
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build();
            var response = client.send(request,
                    java.net.http.HttpResponse.BodyHandlers.discarding());
            System.out.println("webhook: POST " + webhook + " -> HTTP " + response.statusCode());
        } catch (Exception e) {
            System.err.println("webhook failed (analysis unaffected): " + e.getMessage());
        }
    }

    /** Cluster mode: per-node analysis + cross-fleet comparison; writes the same artifacts. */
    private Integer runCluster(AnalysisOptions opts) throws Exception {
        Map<String, DumpSeries> nodes = new java.util.LinkedHashMap<>();
        List<String> specs = new ArrayList<>();
        if (clusterSpecs != null) specs.addAll(clusterSpecs);
        if (clusterManifest != null) {
            for (String line : Files.readAllLines(clusterManifest)) {
                if (!line.isBlank() && !line.startsWith("#")) specs.add(line.trim());
            }
        }
        DumpSetLoader loader = new DumpSetLoader();
        for (String spec : specs) {
            int eq = spec.indexOf('=');
            if (eq <= 0) {
                System.err.println("--cluster needs name=glob, got: " + spec);
                return 2;
            }
            String name = spec.substring(0, eq);
            List<Path> nodeFiles = expandGlob(spec.substring(eq + 1));
            if (nodeFiles.isEmpty()) {
                System.err.println("cluster node " + name + ": no files match " + spec.substring(eq + 1));
                return 3;
            }
            nodes.put(name, loader.load(nodeFiles));
        }
        AnalysisEngine engine = new AnalysisEngine(opts,
                idlePatternsFile != null ? IdlePatterns.withUserFile(idlePatternsFile) : null,
                frameMeaningsFile != null ? FrameMeanings.withUserFile(frameMeaningsFile) : null,
                Rule.merged(ruleFiles));
        Map<String, Object> cluster = new com.tda.core.analysis.ClusterAnalyzer(engine).analyze(nodes);

        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("tool", Map.of("name", "tda", "version", AnalysisEngine.VERSION));
        result.put("generatedAt", java.time.Instant.now().toString());
        result.put("cluster", cluster);

        if (jsonOut != null) {
            Files.writeString(jsonOut, Json.write(result), StandardCharsets.UTF_8);
            System.out.println("JSON written to " + jsonOut);
        }
        if (htmlOut != null) {
            Files.writeString(htmlOut, new HtmlReport().render(result,
                    "Thread Dump Analysis — cluster"), StandardCharsets.UTF_8);
            System.out.println("HTML report written to " + htmlOut);
        }
        System.out.printf("Cluster: %d node(s) analyzed%n", nodes.size());
        for (Object o : (List<?>) cluster.get("outliers")) {
            System.out.println("  OUTLIER: " + ((Map<?, ?>) o).get("explanation"));
        }
        if (((List<?>) cluster.get("outliers")).isEmpty()) {
            System.out.println("  no outliers - the fleet behaves uniformly");
        }
        return 0;
    }

    private static List<Path> expandGlob(String glob) throws Exception {
        Path p = Path.of(glob);
        if (Files.isRegularFile(p)) return List.of(p);
        Path dir = p.getParent() != null ? p.getParent() : Path.of(".");
        String pattern = p.getFileName().toString();
        var matcher = dir.getFileSystem().getPathMatcher("glob:" + pattern);
        if (!Files.isDirectory(dir)) return List.of();
        try (var stream = Files.list(dir)) {
            return stream.filter(f -> matcher.matches(f.getFileName()))
                    .sorted().collect(java.util.stream.Collectors.toList());
        }
    }

    /** Records the analysis into local incident memory and attaches similar past incidents. */
    @SuppressWarnings("unchecked")
    private void recordHistory(Map<String, Object> result, Map<String, Object> baselineDoc) {
        if (noHistory) return;
        try (HistoryStore store = new HistoryStore(
                historyDb != null ? historyDb : HistoryStore.defaultPath())) {
            java.util.Set<String> hashes = new java.util.LinkedHashSet<>();
            for (Map<String, Object> d : (List<Map<String, Object>>) (List<?>) result.get("dumps")) {
                for (Map<String, Object> g : (List<Map<String, Object>>) (List<?>) d.get("topStacks")) {
                    hashes.add(String.valueOf(g.get("hash")));
                }
            }
            var similar = store.similar(hashes, HistoryStore.SIMILARITY_THRESHOLD);
            if (!similar.isEmpty()) {
                List<Object> rows = new ArrayList<>();
                for (var s : similar) {
                    rows.add(Map.of("id", s.id(), "label", s.label() == null ? "" : s.label(),
                            "date", s.ts().toString(), "overlap", s.overlap(),
                            "sharedStacks", s.sharedHashes()));
                }
                result.put("similarIncidents", rows);
                System.out.printf("  %d similar past incident(s) found in history "
                        + "(see the report's Similar past incidents section)%n", similar.size());
            }
            Map<String, Object> summary = new java.util.LinkedHashMap<>();
            Map<String, Integer> sev = new java.util.LinkedHashMap<>();
            List<String> titles = new ArrayList<>();
            for (Map<String, Object> f : (List<Map<String, Object>>) (List<?>) result.get("findings")) {
                sev.merge(String.valueOf(f.get("severity")), 1, Integer::sum);
                if (titles.size() < 10) titles.add(f.get("severity") + ": " + f.get("title"));
            }
            summary.put("severities", sev);
            summary.put("topFindings", titles);
            summary.put("dumps", ((List<?>) result.get("dumps")).size());
            store.record(label, hashes, summary, baselineDoc);
        } catch (Exception e) {
            System.err.println("history: " + e.getMessage() + " (analysis unaffected; use "
                    + "--no-history to silence)");
        }
    }

    /** Loads dumps, transparently converting a JFR recording into synthetic dumps. */
    private DumpSeries loadInput() throws Exception {
        if (files.size() == 1 && JfrLoader.looksLikeJfr(files.get(0))) {
            JfrLoader.JfrResult jfr = new JfrLoader().load(files.get(0), Durations.parse(jfrSlice));
            System.out.printf("JFR: %d execution samples -> %d synthetic dumps (%s slices)%n",
                    jfr.executionSamples(), jfr.series().size(), jfr.effectiveSlice());
            jfrExtras = new java.util.LinkedHashMap<>();
            if (!jfr.contention().isEmpty()) jfrExtras.put("jfrContention", jfr.contention());
            if (!jfr.pinned().isEmpty()) jfrExtras.put("jfrPinned", jfr.pinned());
            return jfr.series();
        }
        return new DumpSetLoader().load(files);
    }

    /** JFR jdk.VirtualThreadPinned events become a finding (the JSON dump can't see pinning). */
    @SuppressWarnings("unchecked")
    private void addPinnedFinding(Map<String, Object> result) {
        List<Map<String, Object>> pinned = (List<Map<String, Object>>) result.get("jfrPinned");
        if (pinned == null || pinned.isEmpty()) return;
        double maxMs = pinned.stream()
                .mapToDouble(p -> ((Number) p.getOrDefault("durationMs", 0)).doubleValue()).max().orElse(0);
        Map<String, Object> f = new java.util.LinkedHashMap<>();
        f.put("id", "virtual-thread-pinned");
        f.put("severity", "WARNING");
        f.put("title", pinned.size() + " virtual-thread pinning event(s), max "
                + Math.round(maxMs) + " ms");
        f.put("detail", "JFR recorded virtual threads pinned to their carrier (synchronized "
                + "block or native frame during a blocking operation). While pinned, the carrier "
                + "platform thread is consumed and cannot run other virtual threads - enough "
                + "pinning recreates platform-thread starvation.");
        f.put("recommendation", "Replace synchronized with ReentrantLock on the pinning paths "
                + "(the frames in the evidence), or move blocking calls outside synchronized "
                + "regions. -Djdk.tracePinnedThreads=full prints offenders at runtime.");
        Map<String, Object> ev = new java.util.LinkedHashMap<>();
        ev.put("events", pinned.size());
        ev.put("maxDurationMs", Math.round(maxMs));
        Object frames = pinned.get(0).get("frames");
        if (frames != null) ev.put("frames", frames);
        ev.put("confidence", "high");
        ev.put("whyNotFalsePositive", "jdk.VirtualThreadPinned events are emitted by the JVM "
                + "only when a virtual thread actually failed to unmount");
        f.put("evidence", ev);
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) result.get("findings");
        findings.add(f);
        findings.sort(java.util.Comparator.comparingInt(x ->
                switch (String.valueOf(x.get("severity"))) {
                    case "CRITICAL" -> 0;
                    case "WARNING" -> 1;
                    default -> 2;
                }));
    }

    AnalysisOptions buildOptions() {
        AnalysisOptions opts = new AnalysisOptions();
        opts.stuckK = stuckK;
        opts.fingerprintDepth = fingerprintDepth;
        opts.topStacks = topStacks;
        opts.criticalVictims = criticalVictims;
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
        for (Object o : (List<?>) result.getOrDefault("qualityNotes", List.of())) {
            Map<String, Object> n = (Map<String, Object>) o;
            System.out.printf("  quality [%s]: %s%n", n.get("level"), n.get("message"));
        }
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
        Map<String, Object> ser = (Map<String, Object>) result.get("series");
        if (ser != null) {
            List<?> stuck = (List<?>) ser.get("stuckThreads");
            for (Object o : stuck) {
                Map<String, Object> st = (Map<String, Object>) o;
                System.out.printf("  STUCK: \"%s\" unchanged for %s consecutive dumps (%s..%s), states=%s%n",
                        st.get("name"), st.get("dumpsUnchanged"), st.get("fromDump"),
                        st.get("toDump"), st.get("states"));
            }
            List<?> holders = (List<?>) ser.get("persistentLockHolders");
            for (Object o : holders) {
                Map<String, Object> h = (Map<String, Object>) o;
                System.out.printf("  PERSISTENT LOCK HOLDER: \"%s\" holds %s across dumps %s, starved %s thread(s)%n",
                        h.get("holder"), h.get("lockClass"), h.get("dumps"), h.get("starvedTotal"));
            }
            for (Object o : (List<?>) ser.get("poolTrends")) {
                Map<String, Object> t = (Map<String, Object>) o;
                if (Boolean.TRUE.equals(t.get("leakSuspect"))) {
                    System.out.printf("  THREAD-LEAK SUSPECT: pool \"%s\" grew monotonically %s%n",
                            t.get("pool"), t.get("counts"));
                }
            }
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
