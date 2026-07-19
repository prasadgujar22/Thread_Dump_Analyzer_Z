package com.tda.core;

import com.tda.core.analysis.classify.IdlePatterns;
import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.analysis.pattern.Finding;
import com.tda.core.analysis.pattern.PatternContext;
import com.tda.core.analysis.pattern.PatternLibrary;
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

    public AnalysisEngine(AnalysisOptions options) {
        this(options, null);
    }

    /** @param idlePatterns idle-pattern knowledge base; null uses the bundled defaults. */
    public AnalysisEngine(AnalysisOptions options, IdlePatterns idlePatterns) {
        this.options = options;
        this.classifier = new ThreadClassifier(idlePatterns);
    }

    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH) {
        return analyze(series, topH, null);
    }

    /** @param baselineDoc a saved healthy-series baseline to diff against, or null. */
    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH,
                                       Map<String, Object> baselineDoc) {
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
        root.put("series", sr.json);

        PatternContext ctx = new PatternContext(series, graphs, deadlocksPerDump,
                sr.verdicts, sr.holders, sr.trends, options);
        List<Object> findings = new ArrayList<>();
        for (Finding f : new PatternLibrary().run(ctx)) findings.add(f.toJson());
        root.put("findings", findings);
        return root;
    }

    private record SeriesResults(Map<String, Object> json,
                                 List<StuckClassifier.Verdict> verdicts,
                                 List<PersistentLockHolders.Holder> holders,
                                 List<PoolTrend.Trend> trends) {}

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
        if (series.size() > 1) {
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
        }

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
            poolRows.add(row);
        }
        m.put("pools", poolRows);

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
            if (!t.frames().isEmpty()) {
                String key = Long.toHexString(t.stackHash());
                stackTable.computeIfAbsent(key, k -> frameList(t));
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

    private List<String> frameList(ThreadInfo t) {
        List<String> frames = new ArrayList<>();
        for (StackFrame f : t.frames()) {
            if (frames.size() >= options.maxFramesShown) break;
            frames.add(f.raw());
        }
        return frames;
    }

    private static List<String> cap(List<String> in, int max) {
        return in.size() <= max ? in : in.subList(0, max);
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
