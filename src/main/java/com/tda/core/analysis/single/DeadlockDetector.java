package com.tda.core.analysis.single;

import com.tda.core.model.ThreadDump;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Deadlock detection from two independent sources:
 * <ol>
 *   <li>the JVM's own "Found one Java-level deadlock" report (already parsed into the model)</li>
 *   <li>cycle detection over the wait-for graph - catches cycles the JVM misses, e.g. mixed
 *       monitor + ReentrantLock deadlocks on JDK 8 where the VM report only covers monitors</li>
 * </ol>
 */
public final class DeadlockDetector {

    public record Cycle(List<String> threadNames, String source) {} // source: "jvm" | "wait-for-graph"

    public List<Cycle> detect(ThreadDump dump, LockGraph graph) {
        List<Cycle> out = new ArrayList<>();
        Set<Set<String>> seen = new HashSet<>();
        for (List<String> cycle : dump.jvmDeadlockCycles()) {
            if (seen.add(new TreeSet<>(cycle))) out.add(new Cycle(List.copyOf(cycle), "jvm"));
        }
        for (List<String> cycle : findCycles(graph.waitsFor())) {
            if (seen.add(new TreeSet<>(cycle))) out.add(new Cycle(cycle, "wait-for-graph"));
        }
        return out;
    }

    /** Finds every distinct cycle in the (out-degree ≤ 1) waits-for map. */
    static List<List<String>> findCycles(Map<String, String> waitsFor) {
        List<List<String>> cycles = new ArrayList<>();
        Set<String> resolved = new HashSet<>();
        for (String start : waitsFor.keySet()) {
            if (resolved.contains(start)) continue;
            // walk the single outgoing chain, watching for a revisit within this walk
            Map<String, Integer> pos = new HashMap<>();
            List<String> path = new ArrayList<>();
            String cur = start;
            while (cur != null && !resolved.contains(cur) && !pos.containsKey(cur)) {
                pos.put(cur, path.size());
                path.add(cur);
                cur = waitsFor.get(cur);
            }
            if (cur != null && pos.containsKey(cur)) {
                cycles.add(new ArrayList<>(new LinkedHashSet<>(path.subList(pos.get(cur), path.size()))));
            }
            resolved.addAll(path);
        }
        return cycles;
    }
}
