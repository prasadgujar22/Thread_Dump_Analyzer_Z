package com.tda.core.analysis.middleware;

import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Per-dump health snapshot of one middleware worker pool: how many threads exist, how many
 * are doing application work (not idle-classified, not JVM housekeeping), how many sit
 * BLOCKED, and container-specific markers. Shared by the WebLogic/Tomcat/WebSphere analyzers
 * and the report panel builder so findings and panels can never disagree.
 */
final class PoolHealth {

    record Snapshot(int dumpIndex, int total, int busy, int blocked, int stuckMarked,
                    int standby, List<String> busyThreads) {
        boolean saturated() { return total > 0 && busy >= total && standby == 0; }
    }

    private PoolHealth() {}

    /** Snapshot of all threads in {@code dump} whose name matches {@code member}. */
    static Snapshot snapshot(ThreadDump dump, int dumpIndex, Predicate<String> member,
                             ThreadClassifier classifier) {
        int total = 0, busy = 0, blocked = 0, stuck = 0, standby = 0;
        List<String> busyThreads = new ArrayList<>();
        for (ThreadInfo t : dump.threads()) {
            if (!member.test(t.name())) continue;
            total++;
            if (t.name().contains("[STUCK]") || t.name().contains("[HOGGING]")) stuck++;
            if (t.name().contains("[STANDBY]")) standby++;
            if (t.state() == ThreadState.BLOCKED) blocked++;
            if (classifier.classify(t).kind() == ThreadClassifier.Kind.APPLICATION
                    && !t.frames().isEmpty()) {
                busy++;
                if (busyThreads.size() < 10) busyThreads.add(t.name());
            }
        }
        return new Snapshot(dumpIndex, total, busy, blocked, stuck, standby, busyThreads);
    }

    /** True when every dump in the series shows a saturated snapshot (and there are ≥2). */
    static boolean saturatedThroughout(List<Snapshot> snaps) {
        if (snaps.size() < 2) return false;
        for (Snapshot s : snaps) if (!s.saturated()) return false;
        return true;
    }

    static int maxBlocked(List<Snapshot> snaps) {
        int max = 0;
        for (Snapshot s : snaps) max = Math.max(max, s.blocked());
        return max;
    }

    static Snapshot worst(List<Snapshot> snaps) {
        Snapshot worst = snaps.get(0);
        for (Snapshot s : snaps) {
            if (s.busy() > worst.busy() || (s.busy() == worst.busy() && s.blocked() > worst.blocked())) {
                worst = s;
            }
        }
        return worst;
    }
}
