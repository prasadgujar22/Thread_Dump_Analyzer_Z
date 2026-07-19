package com.tda.core.analysis.series;

import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.model.LockRef;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;
import com.tda.core.model.TopHSample;

import java.util.ArrayList;
import java.util.List;

/**
 * Applies Rules 1-3 and the severity gate (Rule 5) to raw stuck candidates. Only verdicts
 * with {@code genuine() == true} become findings and swimlane flags; idle/housekeeping
 * candidates surface solely as per-thread classifications.
 */
public final class StuckClassifier {

    public enum Kind {
        IDLE,           // Rule 1: known waiting-for-work pattern - never a finding
        HOUSEKEEPING,   // Rule 2: JVM housekeeping - never a finding (exception handled separately)
        NATIVE_WAIT,    // Rule 3a: zero cpu progress in a native frame - INFO at most
        SPINNING,       // Rule 3b: cpu advanced ~ wall clock - busy-wait/infinite loop
        FROZEN,         // persistent RUNNABLE with partial/unknown cpu evidence on app frames
        BLOCKED_CHAIN,  // Rule 3d: persistent BLOCKED on the same monitor with a live holder
        DISCARDED       // JDK 8 fallback without corroboration - not reported
    }

    public record Verdict(StuckThreadDetector.Stuck stuck, Kind kind, String severity,
                          String confidence, String why, int victims) {
        public boolean genuine() {
            return kind == Kind.SPINNING || kind == Kind.FROZEN || kind == Kind.BLOCKED_CHAIN;
        }
    }

    /** cpuΔ/wallΔ at or above this ratio means the thread is actively burning a core. */
    public static final double SPIN_RATIO = 0.70;
    /** cpuΔ below this fraction of wall clock (and below 100 ms) counts as "no progress". */
    public static final double IDLE_RATIO = 0.05;

    private final ThreadClassifier classifier;
    private final PoolGrouper pools;
    private final int criticalVictims;

    public StuckClassifier(ThreadClassifier classifier, PoolGrouper pools, int criticalVictims) {
        this.classifier = classifier;
        this.pools = pools;
        this.criticalVictims = Math.max(1, criticalVictims);
    }

    public List<Verdict> classify(List<StuckThreadDetector.Stuck> candidates,
                                  SeriesIndex index, List<LockGraph> graphs,
                                  List<TopHSample> topH) {
        List<Verdict> out = new ArrayList<>();
        for (StuckThreadDetector.Stuck st : candidates) {
            out.add(classifyOne(st, index, graphs, topH));
        }
        return out;
    }

    private Verdict classifyOne(StuckThreadDetector.Stuck st, SeriesIndex index,
                                List<LockGraph> graphs, List<TopHSample> topH) {
        ThreadInfo[] occ = index.occurrences().get(st.key());
        ThreadInfo last = occ != null ? occ[st.toDump()] : null;

        // Rule 2 - housekeeping; exception: BLOCKED on an application-owned monitor
        if (last != null && ThreadClassifier.isHousekeepingName(last.name())) {
            if (st.states().contains(ThreadState.BLOCKED.name())) {
                int victims = waiterCount(last, graphs.get(st.toDump()));
                return new Verdict(st, Kind.BLOCKED_CHAIN, "WARNING", "high",
                        "a JVM housekeeping thread should never be BLOCKED on an application "
                        + "monitor - while it waits, its duty (finalization, reference "
                        + "processing) is stalled", victims);
            }
            return new Verdict(st, Kind.HOUSEKEEPING, null, "high",
                    "JVM housekeeping thread on its normal duty stack", 0);
        }

        // Rule 1 - idle-pattern knowledge base
        if (last != null) {
            ThreadClassifier.Classification c = classifier.classify(last);
            if (c.kind() == ThreadClassifier.Kind.IDLE) {
                return new Verdict(st, Kind.IDLE, null, "high",
                        "top frames match the known pattern \"" + c.label()
                        + "\" - parked in the kernel waiting for work, not making progress "
                        + "by design", 0);
            }
        }

        // Rule 3d - persistent BLOCKED chain
        if (st.states().contains(ThreadState.BLOCKED.name()) && last != null) {
            LockGraph g = graphs.get(st.toDump());
            LockRef waited = last.waitingOnLock();
            ThreadInfo holder = waited != null ? g.holderOf(waited.address()) : null;
            int coVictims = waiterCount(last, g);
            String sev = coVictims >= criticalVictims ? "CRITICAL" : "WARNING";
            String why = holder != null
                    ? "blocked on the same monitor across " + st.runLength() + " dumps with a "
                      + "live holder (\"" + SeriesIndex.normalizedName(holder.name()) + "\") and "
                      + coVictims + " thread(s) waiting on that monitor - real contention, not idling"
                    : "blocked on the same monitor across " + st.runLength()
                      + " dumps; the holder is not visible in the dump (possibly a VM-internal owner)";
            return new Verdict(st, Kind.BLOCKED_CHAIN, sev, holder != null ? "high" : "medium",
                    why, coVictims);
        }

        // Rule 3a/3b - cpu-delta corroboration (JDK 11+ dumps)
        Double cpuDelta = st.cpuDeltaMillis();
        Double wall = st.wallClockSeconds();
        if (cpuDelta != null && wall != null && wall > 0) {
            double wallMs = wall * 1000.0;
            double ratio = cpuDelta / wallMs;
            if (ratio <= IDLE_RATIO && cpuDelta < 100.0 && st.topFrameNative()) {
                return new Verdict(st, Kind.NATIVE_WAIT, "INFO", "high",
                        "cpu advanced only " + fmt(cpuDelta) + " ms over " + fmt(wallMs)
                        + " ms of wall clock while parked in a native frame - a kernel wait, "
                        + "not a stuck computation", 0);
            }
            if (ratio >= SPIN_RATIO) {
                int victims = heldVictims(last, graphs.get(st.toDump()));
                String sev = victims > 0 ? "CRITICAL" : "WARNING";
                return new Verdict(st, Kind.SPINNING, sev, "high",
                        "cpu advanced " + fmt(cpuDelta) + " ms over " + fmt(wallMs)
                        + " ms of wall clock (" + Math.round(ratio * 100)
                        + "%) on an unchanged stack - this thread is burning a core in a loop"
                        + (victims > 0 ? " while holding a lock " + victims + " thread(s) wait on" : ""),
                        victims);
            }
            return new Verdict(st, Kind.FROZEN, "WARNING", "medium",
                    "stack unchanged across " + st.runLength() + " dumps with partial cpu progress ("
                    + fmt(cpuDelta) + " ms over " + fmt(wallMs) + " ms) - slow or intermittent "
                    + "progress on one operation", heldVictims(last, graphs.get(st.toDump())));
        }

        // JDK 8: use top -H as the cpu evidence when supplied
        if (last != null && topH != null && !topH.isEmpty()) {
            for (TopHSample s : topH) {
                if (s.pid() == last.nidDecimal()) {
                    if (s.cpuPercent() >= 50.0) {
                        int victims = heldVictims(last, graphs.get(st.toDump()));
                        return new Verdict(st, Kind.SPINNING,
                                victims > 0 ? "CRITICAL" : "WARNING", "medium",
                                "top -H shows " + s.cpuPercent() + "% CPU on this nid while the "
                                + "stack never changes - busy loop", victims);
                    }
                    if (s.cpuPercent() <= 2.0 && st.topFrameNative()) {
                        return new Verdict(st, Kind.NATIVE_WAIT, "INFO", "medium",
                                "top -H shows " + s.cpuPercent() + "% CPU - a native wait, "
                                + "not a stuck computation", 0);
                    }
                }
            }
        }

        // Rule 3c - JDK 8 fallback: no cpu evidence at all
        boolean recognizedPool = last != null && pools.poolOf(last.name()) != null;
        boolean appFrames = hasApplicationFrames(last);
        if (recognizedPool || appFrames) {
            return new Verdict(st, Kind.FROZEN, "WARNING", "medium",
                    "no cpu fields in these dumps (JDK 8 format), but the frozen stack "
                    + (appFrames ? "contains application frames" : "belongs to a recognized worker pool")
                    + " and matches no known idle pattern - supply top -H for CPU corroboration",
                    heldVictims(last, graphs.get(st.toDump())));
        }
        return new Verdict(st, Kind.DISCARDED, null, "low",
                "persistent fingerprint but no idle-pattern match, no cpu evidence, no "
                + "application frames - insufficient corroboration to report", 0);
    }

    /** Waiters on the monitor this thread is blocked on (its co-victims + itself). */
    private int waiterCount(ThreadInfo t, LockGraph g) {
        LockRef w = t.waitingOnLock();
        if (w == null) return 0;
        for (LockGraph.Contention c : g.contendedLocks()) {
            if (c.address().equals(w.address())) return c.waiters().size();
        }
        return 0;
    }

    /** Threads transitively blocked behind locks this thread holds. */
    private int heldVictims(ThreadInfo t, LockGraph g) {
        if (t == null) return 0;
        Integer v = g.transitiveVictimCounts().get(t.name());
        return v != null ? v : 0;
    }

    private boolean hasApplicationFrames(ThreadInfo t) {
        if (t == null) return false;
        for (StackFrame f : t.frames()) {
            if (ThreadClassifier.isApplicationFrame(f.classFqn())) return true;
        }
        return false;
    }

    private static String fmt(double d) {
        return String.valueOf(Math.round(d * 100.0) / 100.0);
    }
}
