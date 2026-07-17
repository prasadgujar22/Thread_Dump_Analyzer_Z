package com.tda.core.analysis.single;

import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.EnumMap;
import java.util.Map;

/** Thread-state counts for one dump (Java threads; VM threads counted separately). */
public final class StateDistribution {

    public record Result(int total, int daemon, int vmThreads, Map<ThreadState, Integer> counts) {
        public double percent(ThreadState s) {
            int c = counts.getOrDefault(s, 0);
            return total == 0 ? 0 : 100.0 * c / total;
        }
    }

    public Result analyze(ThreadDump dump) {
        Map<ThreadState, Integer> counts = new EnumMap<>(ThreadState.class);
        int daemon = 0, vm = 0, total = 0;
        for (ThreadInfo t : dump.threads()) {
            if (t.isVmThread()) { vm++; continue; }
            total++;
            if (t.isDaemon()) daemon++;
            counts.merge(t.state(), 1, Integer::sum);
        }
        return new Result(total, daemon, vm, counts);
    }
}
