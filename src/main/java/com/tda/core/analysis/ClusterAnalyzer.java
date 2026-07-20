package com.tda.core.analysis;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Cluster mode: each node's series is analyzed independently, then compared across the
 * fleet. Outlier scoring is deterministic and explainable - state-distribution divergence
 * from the fleet median, recurring stacks unique to one node, pool-utilization outliers -
 * and every outlier is a sentence a human can check.
 */
public final class ClusterAnalyzer {

    /** State share divergence (percentage points) from the fleet median that flags a node. */
    public static final double STATE_DIVERGENCE_PP = 20.0;
    /** Pool busy%% divergence from the fleet median that flags a node. */
    public static final double POOL_DIVERGENCE_PP = 30.0;
    /** A unique recurring stack needs at least this many threads to flag a node. */
    public static final int UNIQUE_STACK_MIN_COUNT = 5;

    private final AnalysisEngine engine;

    public ClusterAnalyzer(AnalysisEngine engine) {
        this.engine = engine;
    }

    public Map<String, Object> analyze(Map<String, DumpSeries> nodes) {
        return analyze(nodes, false);
    }

    /** @param includeReports embed each node's full analysis for report drill-down
     *                        (opt-in: file size scales with node count) */
    @SuppressWarnings("unchecked")
    public Map<String, Object> analyze(Map<String, DumpSeries> nodes, boolean includeReports) {
        Map<String, Object> nodeReports = new LinkedHashMap<>();
        List<Map<String, Object>> nodeRows = new ArrayList<>();
        Map<String, Map<String, Double>> statePctByNode = new LinkedHashMap<>();
        Map<String, Map<String, Integer>> stacksByNode = new LinkedHashMap<>();   // hash -> count
        Map<String, Map<String, List<String>>> stackFramesByNode = new LinkedHashMap<>();
        Map<String, Map<String, Double>> poolBusyByNode = new LinkedHashMap<>();

        for (Map.Entry<String, DumpSeries> e : nodes.entrySet()) {
            String node = e.getKey();
            Map<String, Object> result = engine.analyze(e.getValue(), List.of());
            if (includeReports) nodeReports.put(node, result);
            List<Map<String, Object>> dumps = (List<Map<String, Object>>) (List<?>) result.get("dumps");

            // average state distribution (percent) across the node's series
            Map<String, Double> statePct = new LinkedHashMap<>();
            double total = 0;
            for (Map<String, Object> d : dumps) {
                Map<String, Object> states = (Map<String, Object>) d.get("states");
                for (Map.Entry<String, Object> s : states.entrySet()) {
                    statePct.merge(s.getKey(), ((Number) s.getValue()).doubleValue(), Double::sum);
                }
                total += ((Number) d.get("totalThreads")).doubleValue();
            }
            double t = Math.max(1, total);
            statePct.replaceAll((k, v) -> 100.0 * v / t);
            statePctByNode.put(node, statePct);

            // recurring stacks (max count across dumps) + a frames sample per hash
            Map<String, Integer> stacks = new LinkedHashMap<>();
            Map<String, List<String>> frames = new LinkedHashMap<>();
            for (Map<String, Object> d : dumps) {
                for (Map<String, Object> g : (List<Map<String, Object>>) (List<?>) d.get("topStacks")) {
                    String hash = String.valueOf(g.get("hash"));
                    stacks.merge(hash, ((Number) g.get("count")).intValue(), Math::max);
                    frames.putIfAbsent(hash, (List<String>) g.get("frames"));
                }
            }
            stacksByNode.put(node, stacks);
            stackFramesByNode.put(node, frames);

            // pool busy% averaged across dumps
            Map<String, double[]> poolAgg = new LinkedHashMap<>(); // pool -> [busy, count]
            for (Map<String, Object> d : dumps) {
                for (Map<String, Object> p : (List<Map<String, Object>>) (List<?>) d.get("pools")) {
                    double[] a = poolAgg.computeIfAbsent(String.valueOf(p.get("pool")), k -> new double[2]);
                    a[0] += ((Number) p.get("busy")).doubleValue();
                    a[1] += ((Number) p.get("count")).doubleValue();
                }
            }
            Map<String, Double> poolBusy = new LinkedHashMap<>();
            poolAgg.forEach((k, a) -> poolBusy.put(k, a[1] > 0 ? 100.0 * a[0] / a[1] : 0));
            poolBusyByNode.put(node, poolBusy);

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("node", node);
            row.put("dumps", dumps.size());
            row.put("threads", dumps.isEmpty() ? 0
                    : ((Map<String, Object>) dumps.get(dumps.size() - 1)).get("totalThreads"));
            row.put("statePercent", round1(statePct));
            row.put("poolBusyPercent", round1(poolBusy));
            List<Map<String, Object>> topStacks = new ArrayList<>();
            stacks.entrySet().stream()
                    .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                    .limit(5)
                    .forEach(s -> topStacks.add(Map.of("hash", s.getKey(), "count", s.getValue(),
                            "frames", frames.getOrDefault(s.getKey(), List.of()))));
            row.put("topStacks", topStacks);
            Map<String, Integer> sev = new LinkedHashMap<>();
            for (Map<String, Object> f : (List<Map<String, Object>>) (List<?>) result.get("findings")) {
                sev.merge(String.valueOf(f.get("severity")), 1, Integer::sum);
            }
            row.put("findings", sev);
            nodeRows.add(row);
        }

        Map<String, Object> cluster = new LinkedHashMap<>();
        cluster.put("nodes", nodeRows);
        cluster.put("outliers", scoreOutliers(statePctByNode, stacksByNode, stackFramesByNode,
                poolBusyByNode));
        if (includeReports) cluster.put("nodeReports", nodeReports);
        return cluster;
    }

    private List<Map<String, Object>> scoreOutliers(
            Map<String, Map<String, Double>> statePct,
            Map<String, Map<String, Integer>> stacks,
            Map<String, Map<String, List<String>>> stackFrames,
            Map<String, Map<String, Double>> poolBusy) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (statePct.size() < 2) return out;

        // 1) state distribution vs fleet median
        for (ThreadState state : ThreadState.values()) {
            Map<String, Double> shares = new LinkedHashMap<>();
            statePct.forEach((node, m) -> shares.put(node, m.getOrDefault(state.name(), 0.0)));
            double median = median(shares.values());
            for (Map.Entry<String, Double> e : shares.entrySet()) {
                double diff = e.getValue() - median;
                if (Math.abs(diff) > STATE_DIVERGENCE_PP) {
                    out.add(outlier(e.getKey(), "state-distribution", String.format(
                            "node %s diverges: %.0f%% of threads %s (fleet median: %.0f%%)",
                            e.getKey(), e.getValue(), state.name(), median)));
                }
            }
        }
        // 2) recurring stacks nobody else has
        for (Map.Entry<String, Map<String, Integer>> e : stacks.entrySet()) {
            for (Map.Entry<String, Integer> s : e.getValue().entrySet()) {
                if (s.getValue() < UNIQUE_STACK_MIN_COUNT) continue;
                boolean elsewhere = stacks.entrySet().stream()
                        .anyMatch(o -> !o.getKey().equals(e.getKey())
                                && o.getValue().containsKey(s.getKey()));
                if (!elsewhere) {
                    List<String> frames = stackFrames.get(e.getKey()).getOrDefault(s.getKey(), List.of());
                    String where = frames.isEmpty() ? "an unrecognized stack"
                            : frames.get(0).replaceAll("\\(.*", "");
                    out.add(outlier(e.getKey(), "unique-stack", String.format(
                            "node %s diverges: %d threads share a stack in %s that no other node shows (fleet median: 0)",
                            e.getKey(), s.getValue(), where)));
                }
            }
        }
        // 3) pool utilization vs fleet median
        Set<String> allPools = new LinkedHashSet<>();
        poolBusy.values().forEach(m -> allPools.addAll(m.keySet()));
        for (String pool : allPools) {
            Map<String, Double> busy = new LinkedHashMap<>();
            poolBusy.forEach((node, m) -> {
                if (m.containsKey(pool)) busy.put(node, m.get(pool));
            });
            if (busy.size() < 2) continue;
            double median = median(busy.values());
            for (Map.Entry<String, Double> e : busy.entrySet()) {
                if (Math.abs(e.getValue() - median) > POOL_DIVERGENCE_PP) {
                    out.add(outlier(e.getKey(), "pool-utilization", String.format(
                            "node %s diverges: pool \"%s\" is %.0f%% busy (fleet median: %.0f%%)",
                            e.getKey(), pool, e.getValue(), median)));
                }
            }
        }
        return out;
    }

    private Map<String, Object> outlier(String node, String kind, String explanation) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("node", node);
        m.put("kind", kind);
        m.put("explanation", explanation);
        return m;
    }

    private static double median(java.util.Collection<Double> values) {
        List<Double> sorted = new ArrayList<>(values);
        sorted.sort(Double::compare);
        int n = sorted.size();
        return n == 0 ? 0 : n % 2 == 1 ? sorted.get(n / 2)
                : (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2.0;
    }

    private static Map<String, Object> round1(Map<String, Double> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(k, Math.round(v * 10) / 10.0));
        return out;
    }
}
