package com.tda.core;

import com.tda.core.analysis.classify.FrameMeanings;
import com.tda.core.analysis.classify.IdlePatterns;
import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.analysis.middleware.MiddlewareDetector;
import com.tda.core.analysis.middleware.MiddlewarePanel;
import com.tda.core.analysis.pattern.Finding;
import com.tda.core.analysis.pattern.PatternContext;
import com.tda.core.analysis.pattern.PatternLibrary;
import com.tda.core.analysis.pattern.Rule;
import com.tda.core.analysis.series.Baseline;
import com.tda.core.analysis.series.StuckClassifier;
import com.tda.core.analysis.series.PersistentLockHolders;
import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.SeriesIndex;
import com.tda.core.analysis.series.StuckThreadDetector;
import com.tda.core.analysis.single.CpuAttribution;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.analysis.single.StackDeduplicator;
import com.tda.core.analysis.single.StateDistribution;
import com.tda.core.model.DumpSeries;
import com.tda.core.parse.GcLogParser;
import com.tda.core.model.LockRef;
import com.tda.core.model.ParseIssue;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.TopHSample;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates all analyzers over a {@link DumpSeries} and produces the canonical
 * JSON-shaped result tree ({@code Map/List/String/Number}) that the JSON export,
 * the HTML report, and the web UI all consume.
 */
public final class AnalysisEngine {

    public static final String VERSION = "1.0.0";

    private final AnalysisOptions options;
    private final ThreadClassifier classifier;
    private final FrameMeanings meanings;
    private final List<Rule> rules;

    public AnalysisEngine(AnalysisOptions options) {
        this(options, null, null, null);
    }

    public AnalysisEngine(AnalysisOptions options, IdlePatterns idlePatterns) {
        this(options, idlePatterns, null, null);
    }

    /** null idlePatterns/meanings/rules fall back to the bundled defaults. */
    public AnalysisEngine(AnalysisOptions options, IdlePatterns idlePatterns,
                          FrameMeanings meanings, List<Rule> rules) {
        this.options = options;
        this.classifier = new ThreadClassifier(idlePatterns);
        this.meanings = meanings != null ? meanings : FrameMeanings.loadDefault();
        this.rules = rules != null ? rules : Rule.loadBundled();
    }

    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH) {
        return analyze(series, topH, null, List.of());
    }

    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH,
                                       Map<String, Object> baselineDoc) {
        return analyze(series, topH, baselineDoc, List.of());
    }

    /**
     * @param baselineDoc a saved healthy-series baseline to diff against, or null
     * @param gcPauses    stop-the-world windows parsed from GC/safepoint logs; used for
     *                    chart overlay bands and to reattribute frozen threads to pauses
     */
    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH,
                                       Map<String, Object> baselineDoc,
                                       List<GcLogParser.PauseWindow> gcPauses) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("tool", Map.of("name", "tda", "version", VERSION));
        root.put("generatedAt", Instant.now().toString());
        root.put("options", options.toJson());

        PoolGrouper pools = new PoolGrouper(options.poolPatterns);

        List<LockGraph> graphs = new ArrayList<>();
        List<List<DeadlockDetector.Cycle>> deadlocksPerDump = new ArrayList<>();
        for (ThreadDump d : series.dumps()) {
            LockGraph g = LockGraph.build(d);
            graphs.add(g);
            deadlocksPerDump.add(new DeadlockDetector().detect(d, g));
        }

        List<Object> dumps = new ArrayList<>();
        for (int i = 0; i < series.size(); i++) {
            dumps.add(analyzeDump(series.get(i), pools, topH, graphs.get(i), deadlocksPerDump.get(i)));
        }
        root.put("dumps", dumps);

        List<Object> quality = new ArrayList<>();
        for (var note : new com.tda.core.analysis.DumpQualityValidator().validate(series)) {
            quality.add(Map.of("level", note.level(), "message", note.message()));
        }
        root.put("qualityNotes", quality);

        SeriesResults sr = analyzeSeries(series, pools, graphs, topH, baselineDoc);

        // Reattribution: a frozen-thread verdict whose dump instants all fall inside
        // stop-the-world windows is the pause's fault, not the application's.
        List<StuckClassifier.Verdict> verdicts = sr.verdicts;
        if (!gcPauses.isEmpty()) {
            verdicts = reattributeToPauses(verdicts, series, gcPauses, sr.json);
        }
        root.put("series", sr.json);

        if (!gcPauses.isEmpty()) {
            List<Object> pauseRows = new ArrayList<>();
            for (GcLogParser.PauseWindow w : gcPauses) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("start", w.start().toString());
                row.put("durationMs", w.durationMs());
                row.put("cause", w.cause());
                row.put("kind", w.kind());
                pauseRows.add(row);
            }
            root.put("gcPauses", pauseRows);
        }

        // Which app server produced these dumps: badge + per-pool panel + analyzer gating.
        MiddlewareDetector.Profile middleware = MiddlewareDetector.detect(series);
        root.put("middleware", MiddlewarePanel.build(series, middleware, classifier));

        PatternContext ctx = new PatternContext(series, graphs, deadlocksPerDump,
                verdicts, sr.holders, sr.trends, gcPauses, poolUtilization(series, pools),
                middleware, classifier, options);
        List<Object> findings = new ArrayList<>();
        for (Finding f : new PatternLibrary(rules).run(ctx)) findings.add(f.toJson());

        // compact meanings catalog so the report can annotate call-stack tree nodes
        List<Object> catalog = new ArrayList<>();
        for (FrameMeanings.Meaning m : meanings.entries()) {
            catalog.add(Map.of("category", m.category(), "activity", m.activity(),
                    "frames", m.frames()));
        }
        root.put("meaningsCatalog", catalog);
        root.put("findings", findings);
        return root;
    }

    private record SeriesResults(Map<String, Object> json,
                                 List<StuckClassifier.Verdict> verdicts,
                                 List<PersistentLockHolders.Holder> holders,
                                 List<PoolTrend.Trend> trends) {}

    /** Discards frozen/native-wait verdicts whose whole run coincides with pause windows. */
    @SuppressWarnings("unchecked")
    private List<StuckClassifier.Verdict> reattributeToPauses(
            List<StuckClassifier.Verdict> verdicts, DumpSeries series,
            List<GcLogParser.PauseWindow> pauses, Map<String, Object> seriesJson) {
        List<StuckClassifier.Verdict> out = new ArrayList<>();
        List<String> reattributed = new ArrayList<>();
        for (StuckClassifier.Verdict v : verdicts) {
            boolean pauseArtifact = v.genuine() || v.kind() == StuckClassifier.Kind.NATIVE_WAIT;
            if (pauseArtifact) {
                for (int i = v.stuck().fromDump(); i <= v.stuck().toDump() && pauseArtifact; i++) {
                    var ts = series.get(i).timestamp();
                    pauseArtifact = ts != null
                            && pauses.stream().anyMatch(w -> w.covers(ts, 2000));
                }
            }
            if (pauseArtifact) {
                reattributed.add(v.stuck().name());
                out.add(new StuckClassifier.Verdict(v.stuck(), StuckClassifier.Kind.DISCARDED,
                        null, "high", "every dump in this thread's frozen run was taken inside a "
                        + "GC/safepoint pause window - the whole JVM was stopped, so an unchanged "
                        + "stack is expected; attributed to the pause, not the application",
                        v.victims()));
            } else {
                out.add(v);
            }
        }
        if (!reattributed.isEmpty()) {
            // also drop them from the stuck table + swimlane flags already built
            List<Map<String, Object>> stuckRows =
                    (List<Map<String, Object>>) (List<?>) seriesJson.get("stuckThreads");
            stuckRows.removeIf(r -> reattributed.contains(String.valueOf(r.get("name"))));
            List<Map<String, Object>> timelines =
                    (List<Map<String, Object>>) (List<?>) seriesJson.get("timelines");
            timelines.removeIf(r -> reattributed.contains(String.valueOf(r.get("name")))
                    && List.of("stuck").equals(r.get("flags")));
            seriesJson.put("reattributedToGc", reattributed);
        }
        return out;
    }

    /** Distills this series into a baseline document for later {@code --baseline} diffs. */
    public Map<String, Object> buildBaseline(DumpSeries series) {
        return new Baseline().build(series, new PoolGrouper(options.poolPatterns), options.topStacks);
    }

    private SeriesResults analyzeSeries(DumpSeries series, PoolGrouper pools,
                                        List<LockGraph> graphs, List<TopHSample> topH,
                                        Map<String, Object> baselineDoc) {
        Map<String, Object> s = new LinkedHashMap<>();
        SeriesIndex index = SeriesIndex.build(series);

        // candidates -> Rules 1-3 verdicts; only genuine verdicts become findings/flags
        List<StuckThreadDetector.Stuck> candidates = new StuckThreadDetector(
                options.stuckK, options.fingerprintDepth, options.maxFramesShown)
                .detect(index, series);
        List<StuckClassifier.Verdict> verdicts = new StuckClassifier(
                classifier, pools, options.criticalVictims)
                .classify(candidates, index, graphs, topH);

        List<Object> stuckRows = new ArrayList<>();
        Set<String> flagged = new LinkedHashSet<>();
        Map<String, Set<String>> flagReasons = new LinkedHashMap<>();
        for (StuckClassifier.Verdict v : verdicts) {
            if (!v.genuine()) continue;
            StuckThreadDetector.Stuck st = v.stuck();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", st.name());
            row.put("tid", st.tid());
            row.put("fromDump", st.fromDump());
            row.put("toDump", st.toDump());
            row.put("dumpsUnchanged", st.runLength());
            row.put("states", st.states());
            row.put("fingerprint", st.fingerprint());
            row.put("verdict", v.kind().name());
            row.put("severity", v.severity());
            row.put("confidence", v.confidence());
            row.put("why", v.why());
            if (st.cpuDeltaMillis() != null) row.put("cpuDeltaMillis", st.cpuDeltaMillis());
            if (st.wallClockSeconds() != null) row.put("wallClockSeconds", st.wallClockSeconds());
            if (v.victims() > 0) row.put("victims", v.victims());
            row.put("frozenFrames", st.frozenFrames());
            stuckRows.add(row);
            flag(flagged, flagReasons, st.key(), "stuck");
        }
        s.put("stuckThreads", stuckRows);

        List<PersistentLockHolders.Holder> holderList = new PersistentLockHolders().detect(series, 2);
        List<Object> holderRows = new ArrayList<>();
        for (PersistentLockHolders.Holder h : holderList) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("holder", h.holderName());
            row.put("lockClass", h.lockClass());
            row.put("dumps", h.dumps());
            row.put("waiterCounts", h.waiterCounts());
            row.put("addresses", h.addresses());
            row.put("starvedTotal", h.starvedTotal());
            row.put("sampleWaiters", h.sampleWaiters());
            holderRows.add(row);
            flag(flagged, flagReasons, h.holderKey(), "persistent-lock-holder");
        }
        s.put("persistentLockHolders", holderRows);

        List<PoolTrend.Trend> trendList = new PoolTrend().analyze(series, pools, options.leakMinGrowth);
        List<Object> trendRows = new ArrayList<>();
        for (PoolTrend.Trend t : trendList) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pool", t.pool());
            row.put("counts", t.counts());
            row.put("growth", t.growth());
            row.put("leakSuspect", t.leakSuspect());
            trendRows.add(row);
        }
        s.put("poolTrends", trendRows);

        // Also flag deadlock participants and WebLogic [STUCK]-marked threads for the swimlane.
        for (ThreadDump d : series.dumps()) {
            for (List<String> cycle : d.jvmDeadlockCycles()) {
                for (String name : cycle) {
                    ThreadInfo t = d.findByName(name);
                    if (t != null) flag(flagged, flagReasons, SeriesIndex.keyOf(t), "deadlock");
                }
            }
            for (ThreadInfo t : d.threads()) {
                if (PoolGrouper.isStuckMarked(t.name())) {
                    flag(flagged, flagReasons, SeriesIndex.keyOf(t), "weblogic-stuck-marker");
                }
            }
        }

        // Per-thread state transition timelines for flagged threads (swimlane data).
        List<Object> timelines = new ArrayList<>();
        for (String key : flagged) {
            ThreadInfo[] occ = index.occurrences().get(key);
            if (occ == null) continue;
            List<Object> states = new ArrayList<>();
            for (ThreadInfo t : occ) states.add(t == null ? null : t.state().name());
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", index.displayName(key));
            row.put("states", states);
            row.put("flags", new ArrayList<>(flagReasons.get(key)));
            timelines.add(row);
            if (timelines.size() >= 150) break;
        }
        s.put("timelines", timelines);

        // Full states-per-dump table for every matched thread (searchable in the UI).
        // Emitted for single dumps too - the per-thread state overview must not require
        // a series (it is simply a one-column table then).
        List<Object> all = new ArrayList<>();
        for (String key : index.keys()) {
            ThreadInfo[] occ = index.occurrences().get(key);
            List<Object> states = new ArrayList<>();
            boolean any = false;
            for (ThreadInfo t : occ) {
                if (t != null && t.isVmThread()) { states.add(null); continue; }
                states.add(t == null ? null : t.state().name());
                any |= t != null;
            }
            if (!any) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", index.displayName(key));
            row.put("states", states);
            all.add(row);
        }
        s.put("allTimelines", all);

        if (baselineDoc != null) {
            s.put("baselineDiff", new Baseline().diff(series, pools, options.topStacks, baselineDoc));
        }
        return new SeriesResults(s, verdicts, holderList, trendList);
    }

    private static void flag(Set<String> flagged, Map<String, Set<String>> reasons,
                             String key, String reason) {
        flagged.add(key);
        reasons.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(reason);
    }

    private Map<String, Object> analyzeDump(ThreadDump d, PoolGrouper pools, List<TopHSample> topH,
                                            LockGraph graph, List<DeadlockDetector.Cycle> cycles) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", d.indexInSeries());
        m.put("source", d.sourceName());
        m.put("timestamp", d.timestamp() != null ? d.timestamp().toString() : null);
        m.put("banner", d.jvmBanner());

        StateDistribution.Result dist = new StateDistribution().analyze(d);
        m.put("totalThreads", dist.total());
        m.put("daemonThreads", dist.daemon());
        m.put("vmThreads", dist.vmThreads());

        // GC/JIT sanity: worker counts, with a note when they look outsized
        int gc = 0, jit = 0;
        for (ThreadInfo t : d.threads()) {
            String n = t.name();
            if (n.startsWith("GC ") || n.startsWith("G1 ") || n.startsWith("ZGC")
                    || n.startsWith("Shenandoah") || n.contains("(ParallelGC)")
                    || n.startsWith("Gang worker") || n.startsWith("Concurrent Mark-Sweep")) gc++;
            else if (n.contains("CompilerThread") || n.startsWith("Sweeper thread")) jit++;
        }
        m.put("gcThreads", gc);
        m.put("jitThreads", jit);

        // virtual threads (JDK 21+ JSON dumps) + carrier mapping
        int virtualCount = 0;
        Map<String, List<String>> byCarrier = new LinkedHashMap<>();
        for (ThreadInfo t : d.threads()) {
            if (!t.isVirtual()) continue;
            virtualCount++;
            if (t.carrierTid() != null) {
                byCarrier.computeIfAbsent(t.carrierTid(), k -> new ArrayList<>()).add(t.name());
            }
        }
        if (virtualCount > 0) {
            m.put("virtualThreads", virtualCount);
            m.put("platformThreads", dist.total() - virtualCount);
            if (!byCarrier.isEmpty()) {
                List<Object> carriers = new ArrayList<>();
                for (Map.Entry<String, List<String>> e : byCarrier.entrySet()) {
                    String carrierName = d.threads().stream()
                            .filter(t -> !t.isVirtual() && t.javaId() != null
                                    && String.valueOf(t.javaId()).equals(e.getKey()))
                            .map(ThreadInfo::name).findFirst().orElse("tid " + e.getKey());
                    carriers.add(Map.of("carrier", carrierName,
                            "carrierTid", e.getKey(),
                            "count", e.getValue().size(),
                            "virtualThreads", cap(e.getValue(), 10)));
                }
                m.put("carriers", carriers);
            }
        }
        if (gc >= 24 || jit >= 8) {
            m.put("gcJitNote", "unusually many GC/JIT threads (" + gc + " GC, " + jit
                    + " JIT) - check -XX:ParallelGCThreads/-XX:CICompilerCount vs the "
                    + "container's actual CPU quota");
        }
        Map<String, Object> states = new LinkedHashMap<>();
        dist.counts().forEach((k, v) -> states.put(k.name(), v));
        m.put("states", states);

        List<Object> poolRows = new ArrayList<>();
        for (PoolGrouper.PoolStats p : pools.analyze(d)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pool", p.pool());
            row.put("count", p.count());
            Map<String, Object> st = new LinkedHashMap<>();
            p.states().forEach((k, v) -> st.put(k.name(), v));
            row.put("states", st);
            row.put("stuck", p.stuckCount());
            // work-manager utilization: busy = not idle-classified (Rule 1 knowledge base)
            int busy = 0;
            for (String name : p.threadNames()) {
                ThreadInfo t = d.findByName(name);
                if (t != null && classifier.classify(t).kind() == ThreadClassifier.Kind.APPLICATION) busy++;
            }
            row.put("busy", busy);
            row.put("idle", p.count() - busy);
            poolRows.add(row);
        }
        m.put("pools", poolRows);

        // "where is the time going": thread counts per activity category
        Map<String, Integer> categories = new LinkedHashMap<>();
        for (ThreadInfo t : d.javaThreads()) {
            FrameMeanings.Meaning me = meanings.meaningFor(t);
            if (me != null) categories.merge(me.category(), 1, Integer::sum);
        }
        m.put("categories", categories);

        List<Object> stackGroups = new ArrayList<>();
        for (StackDeduplicator.Group g : new StackDeduplicator()
                .analyze(d, options.topStacks, options.maxFramesShown)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("hash", Long.toHexString(g.hash()));
            row.put("count", g.count());
            row.put("frames", g.frames());
            row.put("threads", cap(g.threadNames(), 25));
            Map<String, Object> st = new LinkedHashMap<>();
            g.states().forEach((k, v) -> st.put(k.name(), v));
            row.put("states", st);
            stackGroups.add(row);
        }
        m.put("topStacks", stackGroups);

        List<Object> locks = new ArrayList<>();
        for (LockGraph.Contention c : graph.contendedLocks()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", c.address());
            row.put("class", c.lockClass());
            row.put("holder", c.holder());
            row.put("waiters", c.waiters());
            locks.add(row);
        }
        m.put("contendedLocks", locks);

        Map<String, List<String>> direct = graph.directVictims();
        Map<String, Integer> transitive = graph.transitiveVictimCounts();
        List<Object> blockers = new ArrayList<>();
        transitive.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .forEach(e -> {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("thread", e.getKey());
                    row.put("direct", direct.getOrDefault(e.getKey(), List.of()).size());
                    row.put("transitive", e.getValue());
                    blockers.add(row);
                });
        m.put("topBlockers", blockers);

        List<Object> deadlocks = new ArrayList<>();
        for (DeadlockDetector.Cycle c : cycles) {
            deadlocks.add(Map.of("threads", c.threadNames(), "source", c.source()));
        }
        m.put("deadlocks", deadlocks);

        Map<Long, TopHSample> topByPid = new LinkedHashMap<>();
        if (topH != null) for (TopHSample s : topH) topByPid.put(s.pid(), s);
        List<Object> cpu = new ArrayList<>();
        List<CpuAttribution.Row> cpuRows = new CpuAttribution().analyze(d, topH);
        for (int i = 0; i < cpuRows.size() && i < 40; i++) {
            CpuAttribution.Row r = cpuRows.get(i);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("thread", r.threadName());
            row.put("nid", r.nidHex());
            row.put("nidDec", r.nidDecimal());
            row.put("state", r.state());
            row.put("cpuMillis", r.cpuMillis());
            row.put("elapsedSeconds", r.elapsedSeconds());
            row.put("topPercent", r.cpuPercentFromTop());
            TopHSample s = topByPid.get(r.nidDecimal());
            if (s != null && s.memPercent() > 0) row.put("topMemPercent", s.memPercent());
            cpu.add(row);
        }
        m.put("cpu", cpu);

        // fastThread-style method stats: where threads are executing right now (top frame)
        // and which methods appear anywhere in the stacks
        Map<String, Integer> lastExecuted = new LinkedHashMap<>();
        Map<String, Integer> mostUsed = new LinkedHashMap<>();
        for (ThreadInfo t : d.javaThreads()) {
            if (t.frames().isEmpty()) continue;
            lastExecuted.merge(t.frames().get(0).signature(), 1, Integer::sum);
            for (StackFrame f : t.frames()) mostUsed.merge(f.signature(), 1, Integer::sum);
        }
        m.put("methodStats", Map.of(
                "lastExecuted", topCounts(lastExecuted, 15),
                "mostUsed", topCounts(mostUsed, 15)));

        List<String> issues = new ArrayList<>();
        for (ParseIssue i : d.issues()) issues.add(i.toString());
        m.put("issues", issues);

        // Thread detail with stack dedup: unique stacks stored once, threads reference them.
        Map<String, Object> stackTable = new LinkedHashMap<>();
        List<Object> threads = new ArrayList<>();
        for (ThreadInfo t : d.threads()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", t.name());
            row.put("id", t.javaId());
            row.put("tid", t.tidHex());
            row.put("nid", t.nidHex());
            row.put("nidDec", t.nidDecimal());
            row.put("daemon", t.isDaemon());
            row.put("prio", t.priority());
            row.put("state", t.state().name());
            row.put("stateDetail", t.stateDetail().isEmpty() ? t.headerCondition() : t.stateDetail());
            if (t.cpuMillis() != null) row.put("cpuMillis", t.cpuMillis());
            if (t.elapsedSeconds() != null) row.put("elapsedSeconds", t.elapsedSeconds());
            String pool = pools.poolOf(t.name());
            if (pool != null) row.put("pool", pool);
            ThreadClassifier.Classification cls = classifier.classify(t);
            if (cls.label() != null) row.put("class", cls.label());
            FrameMeanings.Meaning meaning = meanings.meaningFor(t);
            if (meaning != null) {
                row.put("activity", meaning.activity());
                row.put("category", meaning.category());
            }
            if (t.isVirtual()) {
                row.put("virtual", true);
                if (t.carrierTid() != null) row.put("carrier", t.carrierTid());
            }
            if (!t.frames().isEmpty()) {
                // Lock annotations are part of the displayed stack, so the dedup key must
                // include them: threads sharing a frame hash but holding/waiting on
                // different locks must not share one stack entry.
                List<String> lines = annotatedFrameList(t);
                String key = Long.toHexString(t.stackHash());
                if (!t.locks().isEmpty()) key += "-" + Long.toHexString(lineHash(lines));
                stackTable.computeIfAbsent(key, k -> lines);
                row.put("stack", key);
            }
            List<Object> lockRows = new ArrayList<>();
            for (LockRef l : t.locks()) {
                lockRows.add(Map.of("kind", l.kind().name(),
                        "address", l.address() == null ? "" : l.address(),
                        "class", l.className() == null ? "" : l.className()));
            }
            if (!lockRows.isEmpty()) row.put("locks", lockRows);
            threads.add(row);
        }
        m.put("stacks", stackTable);
        m.put("threads", threads);
        return m;
    }

    /**
     * The thread's stack as shown in reports: frames interleaved with their lock
     * annotations exactly like the original dump ({@code - locked <0x...> (a Foo)},
     * {@code - waiting to lock ...}), plus a trailing "Locked ownable synchronizers"
     * block for {@code jstack -l} holds and a "Locked monitors" block for holds whose
     * frame position is unknown (javacore LOCKS-section ownership).
     */
    private List<String> annotatedFrameList(ThreadInfo t) {
        Map<Integer, List<String>> byFrame = new LinkedHashMap<>();
        List<String> synchronizers = new ArrayList<>();
        List<String> unplacedHolds = new ArrayList<>();
        List<String> unplacedWaits = new ArrayList<>();
        for (LockRef l : t.locks()) {
            String cls = l.className() != null ? " (a " + l.className() + ")" : "";
            String line = switch (l.kind()) {
                case LOCKED_MONITOR -> "- locked <" + l.address() + ">" + cls;
                case WAITING_TO_LOCK -> "- waiting to lock <" + l.address() + ">" + cls;
                case WAITING_ON -> "- waiting on <" + l.address() + ">" + cls;
                case PARKING_TO_WAIT_FOR -> "- parking to wait for <" + l.address() + ">" + cls;
                case LOCKED_SYNCHRONIZER -> "- <" + l.address() + ">" + cls;
                case ELIMINATED -> "- eliminated" + cls;
            };
            if (l.kind() == LockRef.Kind.LOCKED_SYNCHRONIZER) {
                synchronizers.add(line);
            } else if (l.frameIndex() >= 0) {
                byFrame.computeIfAbsent(l.frameIndex(), k -> new ArrayList<>()).add(line);
            } else if (l.isWait()) {
                unplacedWaits.add(line); // javacore 3XMTHREADBLOCK - belongs at the top frame
            } else {
                unplacedHolds.add(line); // javacore LOCKS-section hold, frame unknown
            }
        }
        List<String> lines = new ArrayList<>();
        int shown = 0;
        for (int i = 0; i < t.frames().size(); i++) {
            if (shown >= options.maxFramesShown) break;
            lines.add(t.frames().get(i).raw());
            shown++;
            if (i == 0) for (String w : unplacedWaits) lines.add(w);
            for (String a : byFrame.getOrDefault(i, List.of())) lines.add(a);
        }
        if (!unplacedHolds.isEmpty()) {
            lines.add("");
            lines.add("Locked monitors (position in stack unknown):");
            lines.addAll(unplacedHolds);
        }
        if (!synchronizers.isEmpty()) {
            lines.add("");
            lines.add("Locked ownable synchronizers:");
            lines.addAll(synchronizers);
        }
        return lines;
    }

    private static long lineHash(List<String> lines) {
        long h = 0xcbf29ce484222325L;
        for (String s : lines) {
            for (byte b : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
                h ^= b & 0xff;
                h *= 0x100000001b3L;
            }
            h ^= '\n';
            h *= 0x100000001b3L;
        }
        return h;
    }

    private static List<String> cap(List<String> in, int max) {
        return in.size() <= max ? in : in.subList(0, max);
    }

    /** Observed busy/idle utilization per pool across the series (Rule-1 classification). */
    private List<PatternContext.PoolUtil> poolUtilization(DumpSeries series, PoolGrouper pools) {
        Map<String, int[]> agg = new LinkedHashMap<>(); // pool -> [busySum, totalSum, maxSize, blocked]
        for (ThreadDump d : series.dumps()) {
            for (PoolGrouper.PoolStats p : pools.analyze(d)) {
                int[] a = agg.computeIfAbsent(p.pool(), k -> new int[4]);
                int busy = 0;
                for (String name : p.threadNames()) {
                    ThreadInfo t = d.findByName(name);
                    if (t != null && classifier.classify(t).kind() == ThreadClassifier.Kind.APPLICATION) {
                        busy++;
                    }
                }
                a[0] += busy;
                a[1] += p.count();
                a[2] = Math.max(a[2], p.count());
                a[3] += p.states().getOrDefault(com.tda.core.model.ThreadState.BLOCKED, 0);
            }
        }
        List<PatternContext.PoolUtil> out = new ArrayList<>();
        for (Map.Entry<String, int[]> e : agg.entrySet()) {
            int[] a = e.getValue();
            if (a[1] == 0) continue;
            out.add(new PatternContext.PoolUtil(e.getKey(), 100.0 * a[0] / a[1], a[2], a[3]));
        }
        return out;
    }

    private static List<Object> topCounts(Map<String, Integer> counts, int n) {
        List<Object> out = new ArrayList<>();
        counts.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(n)
                .forEach(e -> out.add(Map.of("method", e.getKey(), "count", e.getValue())));
        return out;
    }
}
