package com.tda.core;

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
import java.util.List;
import java.util.Map;

/**
 * Orchestrates all analyzers over a {@link DumpSeries} and produces the canonical
 * JSON-shaped result tree ({@code Map/List/String/Number}) that the JSON export,
 * the HTML report, and the web UI all consume.
 */
public final class AnalysisEngine {

    public static final String VERSION = "1.0.0";

    private final AnalysisOptions options;

    public AnalysisEngine(AnalysisOptions options) {
        this.options = options;
    }

    public Map<String, Object> analyze(DumpSeries series, List<TopHSample> topH) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("tool", Map.of("name", "tda", "version", VERSION));
        root.put("generatedAt", Instant.now().toString());
        root.put("options", options.toJson());

        PoolGrouper pools = new PoolGrouper(options.poolPatterns);
        List<Object> dumps = new ArrayList<>();
        for (ThreadDump d : series.dumps()) {
            dumps.add(analyzeDump(d, pools, topH));
        }
        root.put("dumps", dumps);
        return root;
    }

    private Map<String, Object> analyzeDump(ThreadDump d, PoolGrouper pools, List<TopHSample> topH) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", d.indexInSeries());
        m.put("source", d.sourceName());
        m.put("timestamp", d.timestamp() != null ? d.timestamp().toString() : null);
        m.put("banner", d.jvmBanner());

        StateDistribution.Result dist = new StateDistribution().analyze(d);
        m.put("totalThreads", dist.total());
        m.put("daemonThreads", dist.daemon());
        m.put("vmThreads", dist.vmThreads());
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

        LockGraph graph = LockGraph.build(d);
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
        for (DeadlockDetector.Cycle c : new DeadlockDetector().detect(d, graph)) {
            deadlocks.add(Map.of("threads", c.threadNames(), "source", c.source()));
        }
        m.put("deadlocks", deadlocks);

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
            cpu.add(row);
        }
        m.put("cpu", cpu);

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
}
