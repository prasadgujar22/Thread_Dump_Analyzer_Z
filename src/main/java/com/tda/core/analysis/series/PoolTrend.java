package com.tda.core.analysis.series;

import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Per-pool thread-count trend across the series; monotonic growth marks a thread-leak suspect. */
public final class PoolTrend {

    public record Trend(String pool, List<Integer> counts, boolean leakSuspect, int growth) {}

    public List<Trend> analyze(DumpSeries series, PoolGrouper pools, int leakMinGrowth) {
        Map<String, int[]> counts = new LinkedHashMap<>();
        for (int i = 0; i < series.size(); i++) {
            for (ThreadInfo t : series.get(i).javaThreads()) {
                String pool = pools.poolOf(t.name());
                if (pool == null) continue;
                counts.computeIfAbsent(pool, k -> new int[series.size()])[i]++;
            }
        }
        List<Trend> out = new ArrayList<>();
        for (Map.Entry<String, int[]> e : counts.entrySet()) {
            int[] c = e.getValue();
            boolean monotonic = series.size() >= 3;
            boolean grew = false;
            for (int i = 1; i < c.length; i++) {
                if (c[i] < c[i - 1]) { monotonic = false; break; }
                if (c[i] > c[i - 1]) grew = true;
            }
            int growth = c.length > 0 ? c[c.length - 1] - c[0] : 0;
            List<Integer> list = new ArrayList<>(c.length);
            for (int v : c) list.add(v);
            out.add(new Trend(e.getKey(), list, monotonic && grew && growth >= leakMinGrowth, growth));
        }
        out.sort((a, b) -> Integer.compare(b.growth(), a.growth()));
        return out;
    }
}
