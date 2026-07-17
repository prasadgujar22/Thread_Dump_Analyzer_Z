package com.tda.core.analysis.single;

import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.TopHSample;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-thread CPU attribution. Two sources, used when available:
 * <ul>
 *   <li>the {@code cpu=}/{@code elapsed=} header fields (JDK 11+ dumps)</li>
 *   <li>pasted {@code top -H} output joined on nid: top's PID column is the OS thread id,
 *       which equals the dump's nid in decimal (works for JDK 8 dumps too)</li>
 * </ul>
 */
public final class CpuAttribution {

    public record Row(String threadName, String nidHex, long nidDecimal, String state,
                      Double cpuMillis, Double elapsedSeconds, Double cpuPercentFromTop) {}

    public List<Row> analyze(ThreadDump dump, List<TopHSample> topH) {
        Map<Long, TopHSample> byPid = new HashMap<>();
        if (topH != null) for (TopHSample s : topH) byPid.put(s.pid(), s);
        List<Row> rows = new ArrayList<>();
        for (ThreadInfo t : dump.threads()) {
            TopHSample s = t.nidDecimal() >= 0 ? byPid.get(t.nidDecimal()) : null;
            if (t.cpuMillis() == null && s == null) continue;
            rows.add(new Row(t.name(), t.nidHex(), t.nidDecimal(), t.state().name(),
                    t.cpuMillis(), t.elapsedSeconds(), s != null ? s.cpuPercent() : null));
        }
        rows.sort((a, b) -> Double.compare(score(b), score(a)));
        return rows;
    }

    private double score(Row r) {
        if (r.cpuPercentFromTop() != null) return 1_000_000 + r.cpuPercentFromTop();
        return r.cpuMillis() != null ? r.cpuMillis() : 0;
    }
}
