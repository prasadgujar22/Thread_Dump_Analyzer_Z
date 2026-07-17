package com.tda.core.analysis.single;

import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Groups threads with byte-identical stacks; 300 threads stuck in the same frame become one row. */
public final class StackDeduplicator {

    public record Group(long hash, int count, List<String> threadNames,
                        List<String> frames, Map<ThreadState, Integer> states) {}

    /** Top {@code topN} recurring stacks (only groups with ≥ 2 threads), biggest first. */
    public List<Group> analyze(ThreadDump dump, int topN, int maxFramesShown) {
        Map<Long, List<ThreadInfo>> byHash = new LinkedHashMap<>();
        for (ThreadInfo t : dump.javaThreads()) {
            if (t.frames().isEmpty()) continue;
            byHash.computeIfAbsent(t.stackHash(), k -> new ArrayList<>()).add(t);
        }
        List<Group> groups = new ArrayList<>();
        for (Map.Entry<Long, List<ThreadInfo>> e : byHash.entrySet()) {
            List<ThreadInfo> ts = e.getValue();
            if (ts.size() < 2) continue;
            Map<ThreadState, Integer> states = new EnumMap<>(ThreadState.class);
            List<String> names = new ArrayList<>();
            for (ThreadInfo t : ts) {
                states.merge(t.state(), 1, Integer::sum);
                names.add(t.name());
            }
            List<String> frames = new ArrayList<>();
            for (StackFrame f : ts.get(0).frames()) {
                if (frames.size() >= maxFramesShown) break;
                frames.add(f.raw());
            }
            groups.add(new Group(e.getKey(), ts.size(), names, frames, states));
        }
        groups.sort((a, b) -> Integer.compare(b.count(), a.count()));
        return groups.size() > topN ? groups.subList(0, topN) : groups;
    }
}
