package com.tda.core.analysis.series;

import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.analysis.single.StackDeduplicator;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Baseline mode: distill a known-healthy series into a small JSON document, then diff an
 * incident series against it - state-distribution shifts, pool-count deltas, and recurring
 * stacks that did not exist in the baseline.
 */
public final class Baseline {

    public static final String TYPE = "tda-baseline";

    /** Distills a healthy series into a baseline document (JSON-shaped map). */
    public Map<String, Object> build(DumpSeries series, PoolGrouper pools, int topStacks) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", TYPE);
        b.put("version", 1);
        b.put("dumps", series.size());

        Map<String, Double> statePct = new LinkedHashMap<>();
        double avgThreads = 0;
        Map<String, Double> poolAvg = new LinkedHashMap<>();
        Set<String> stackHashes = new LinkedHashSet<>();
        for (ThreadDump d : series.dumps()) {
            List<ThreadInfo> java = d.javaThreads();
            avgThreads += java.size();
            for (ThreadInfo t : java) {
                statePct.merge(t.state().name(), 1.0, Double::sum);
                String pool = pools.poolOf(t.name());
                if (pool != null) poolAvg.merge(pool, 1.0, Double::sum);
            }
            for (StackDeduplicator.Group g : new StackDeduplicator().analyze(d, topStacks, 1)) {
                stackHashes.add(Long.toHexString(g.hash()));
            }
        }
        int n = Math.max(1, series.size());
        double total = statePct.values().stream().mapToDouble(Double::doubleValue).sum();
        statePct.replaceAll((k, v) -> round2(100.0 * v / Math.max(1.0, total)));
        poolAvg.replaceAll((k, v) -> round2(v / n));
        b.put("avgThreads", round2(avgThreads / n));
        b.put("statePercent", statePct);
        b.put("poolAvg", poolAvg);
        b.put("stackHashes", new ArrayList<>(stackHashes));
        return b;
    }

    /** Diffs an incident series against a saved baseline document. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> diff(DumpSeries incident, PoolGrouper pools, int topStacks,
                                    Map<String, Object> baseline) {
        Map<String, Object> incidentB = build(incident, pools, topStacks);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("baselineDumps", baseline.get("dumps"));
        out.put("incidentDumps", incident.size());
        out.put("avgThreadsBaseline", baseline.get("avgThreads"));
        out.put("avgThreadsIncident", incidentB.get("avgThreads"));

        Map<String, Object> baseStates = (Map<String, Object>) baseline.getOrDefault("statePercent", Map.of());
        Map<String, Double> incStates = (Map<String, Double>) incidentB.get("statePercent");
        List<Object> stateShifts = new ArrayList<>();
        for (ThreadState s : ThreadState.values()) {
            double base = num(baseStates.get(s.name()));
            double inc = incStates.getOrDefault(s.name(), 0.0);
            if (base == 0 && inc == 0) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("state", s.name());
            row.put("baselinePercent", round2(base));
            row.put("incidentPercent", round2(inc));
            row.put("deltaPoints", round2(inc - base));
            stateShifts.add(row);
        }
        out.put("stateShifts", stateShifts);

        Map<String, Object> basePools = (Map<String, Object>) baseline.getOrDefault("poolAvg", Map.of());
        Map<String, Double> incPools = (Map<String, Double>) incidentB.get("poolAvg");
        Set<String> allPools = new LinkedHashSet<>(basePools.keySet());
        allPools.addAll(incPools.keySet());
        List<Object> poolDeltas = new ArrayList<>();
        for (String p : allPools) {
            double base = num(basePools.get(p));
            double inc = incPools.getOrDefault(p, 0.0);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pool", p);
            row.put("baselineAvg", round2(base));
            row.put("incidentAvg", round2(inc));
            row.put("delta", round2(inc - base));
            poolDeltas.add(row);
        }
        poolDeltas.sort((a, b) -> Double.compare(
                Math.abs(num(((Map<String, Object>) b).get("delta"))),
                Math.abs(num(((Map<String, Object>) a).get("delta")))));
        out.put("poolDeltas", poolDeltas);

        Set<String> baseHashes = new LinkedHashSet<>();
        for (Object h : (List<Object>) baseline.getOrDefault("stackHashes", List.of())) {
            baseHashes.add(String.valueOf(h));
        }
        // recurring stacks in the incident that the healthy baseline never showed
        Map<String, Map<String, Object>> newStacks = new LinkedHashMap<>();
        for (ThreadDump d : incident.dumps()) {
            for (StackDeduplicator.Group g : new StackDeduplicator().analyze(d, topStacks, 12)) {
                String hash = Long.toHexString(g.hash());
                if (baseHashes.contains(hash)) continue;
                Map<String, Object> row = newStacks.computeIfAbsent(hash, k -> {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("hash", hash);
                    r.put("frames", g.frames());
                    r.put("maxCount", 0);
                    r.put("dumps", new ArrayList<Integer>());
                    return r;
                });
                row.put("maxCount", Math.max((Integer) row.get("maxCount"), g.count()));
                ((List<Integer>) row.get("dumps")).add(d.indexInSeries());
            }
        }
        out.put("newRecurringStacks", new ArrayList<>(newStacks.values()));
        return out;
    }

    private static double num(Object o) { return o instanceof Number n ? n.doubleValue() : 0.0; }
    private static double round2(double d) { return Math.round(d * 100.0) / 100.0; }
}
