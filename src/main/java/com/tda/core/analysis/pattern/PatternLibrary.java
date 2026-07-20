package com.tda.core.analysis.pattern;

import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.StuckClassifier;
import com.tda.core.analysis.series.StuckThreadDetector;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.analysis.single.PoolGrouper;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;
import com.tda.core.parse.GcLogParser;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.tda.core.analysis.pattern.Finding.Severity.CRITICAL;
import static com.tda.core.analysis.pattern.Finding.Severity.INFO;
import static com.tda.core.analysis.pattern.Finding.Severity.WARNING;

/**
 * The built-in pattern library; runs every detector and returns findings ranked by severity.
 * Frame-scan detectors live in the bundled rules.yaml and run through {@link RuleEngine} -
 * the same machinery user site packs use; graph-/cpu-theoretic detectors stay native.
 */
public final class PatternLibrary {

    private final List<Pattern> patterns;

    public PatternLibrary() {
        this(Rule.loadBundled());
    }

    public PatternLibrary(List<Rule> rules) {
        patterns = List.of(
                new DeadlockPattern(),
                new WebLogicStuckPattern(),
                new StuckThreadPattern(),
                new RuleEngine(rules),
                new NetworkHangPattern(),
                new FinalizerBacklogPattern(),
                new TopBlockerPattern(),
                new ThreadLeakPattern(),
                new GcPausePattern(),
                new PoolSizingPattern(),
                // platform-specific health checks, gated on MiddlewareDetector
                new com.tda.core.analysis.middleware.WebLogicAnalyzer(),
                new com.tda.core.analysis.middleware.TomcatAnalyzer(),
                new com.tda.core.analysis.middleware.WebSphereAnalyzer());
    }

    public List<Finding> run(PatternContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (Pattern p : patterns) out.addAll(p.detect(ctx));
        out.sort(Comparator.comparingInt(f -> f.severity().ordinal()));
        return out;
    }
}

/** Deadlocks are always critical, whether the JVM reported them or the wait-for graph found them. */
final class DeadlockPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            for (DeadlockDetector.Cycle c : ctx.deadlocks().get(i)) {
                out.add(new Finding("deadlock", CRITICAL,
                        "Deadlock: " + c.threadNames().size() + " threads in a lock cycle",
                        "Threads " + c.threadNames() + " each hold a lock the next one needs ("
                                + ("jvm".equals(c.source()) ? "reported by the JVM" : "detected by wait-for-graph cycle analysis")
                                + "). None of them can ever proceed; every thread that needs any of these locks will pile up behind them.",
                        "Fix the lock ordering so all code paths acquire these locks in the same global order, "
                                + "or replace nested locking with a single coarser lock / tryLock with timeout and retry. "
                                + "Until a fix ships, only a JVM restart clears a deadlock.")
                        .evidence("dump", i)
                        .evidence("threads", c.threadNames())
                        .evidence("source", c.source())
                        .evidence("confidence", "high")
                        .evidence("whyNotFalsePositive", "jvm".equals(c.source())
                                ? "the JVM itself verified this lock cycle"
                                : "a closed cycle in the wait-for graph is impossible for healthy threads"));
            }
        }
        return out;
    }
}

/** WebLogic already applied its own stuck-threshold (default 600s) - surface its verdict loudly. */
final class WebLogicStuckPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        Map<String, List<Integer>> stuckDumps = new LinkedHashMap<>();
        Map<String, List<Integer>> hoggingDumps = new LinkedHashMap<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            for (ThreadInfo t : ctx.series().get(i).threads()) {
                if (t.name().contains("[STUCK]")) {
                    stuckDumps.computeIfAbsent(t.name(), k -> new ArrayList<>()).add(i);
                } else if (t.name().contains("[HOGGING]")) {
                    hoggingDumps.computeIfAbsent(t.name(), k -> new ArrayList<>()).add(i);
                }
            }
        }
        List<Finding> out = new ArrayList<>();
        if (!stuckDumps.isEmpty()) {
            out.add(new Finding("weblogic-stuck", CRITICAL,
                    "WebLogic marked " + stuckDumps.size() + " thread(s) [STUCK]",
                    "WebLogic flags a thread [STUCK] after it works a single request longer than the "
                            + "configured StuckThreadMaxTime (default 600s). These threads have been busy on "
                            + "one request for at least that long.",
                    "Inspect each stuck thread's stack (usually an external call without a timeout - JDBC, "
                            + "MQ, HTTP). Add read/connect timeouts to the blocking call, and check the "
                            + "corresponding backend. Consider a WorkManager with max-stuck-thread-time and "
                            + "stuck-thread-work-manager actions for automatic mitigation.")
                    .evidence("threads", new ArrayList<>(stuckDumps.keySet()))
                    .evidence("dumpsSeen", stuckDumps.values().stream().map(List::size).toList())
                    .evidence("confidence", "high")
                    .evidence("whyNotFalsePositive", "WebLogic's own health monitor timed these "
                            + "threads over StuckThreadMaxTime before marking them - the marker is "
                            + "measured, not inferred from one snapshot"));
        }
        if (!hoggingDumps.isEmpty()) {
            out.add(new Finding("weblogic-hogging", WARNING,
                    "WebLogic marked " + hoggingDumps.size() + " thread(s) [HOGGING]",
                    "Hogging threads have held a request noticeably longer than the average and are "
                            + "candidates to become [STUCK].",
                    "Watch these threads across consecutive dumps; investigate their stacks the same way "
                            + "as stuck threads if they do not return to the pool.")
                    .evidence("threads", new ArrayList<>(hoggingDumps.keySet())));
        }
        return out;
    }
}

/**
 * Fingerprint-persistence candidates promoted to findings ONLY after {@code StuckClassifier}
 * ruled out idle patterns and housekeeping and corroborated with cpu deltas (Rules 1-3, 5).
 */
final class StuckThreadPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        if (ctx.stuckVerdicts().isEmpty() || ctx.series().size() < 2) return List.of();
        List<Finding> out = new ArrayList<>();
        for (StuckClassifier.Verdict v : ctx.stuckVerdicts()) {
            StuckThreadDetector.Stuck st = v.stuck();
            if (v.kind() == StuckClassifier.Kind.NATIVE_WAIT) {
                out.add(base(v, "idle-native-wait", INFO,
                        "Persistent native wait (no CPU progress): " + shortName(st.name()),
                        "\"" + st.name() + "\" kept the same native-frame stack across dumps "
                                + st.fromDump() + ".." + st.toDump() + " but consumed almost no CPU - a "
                                + "kernel-level wait the JVM reports as RUNNABLE, not a stuck computation.",
                        "Usually harmless. If this thread is supposed to be serving a request, the remote "
                                + "side is not answering - add a read timeout to the underlying call."));
                continue;
            }
            if (!v.genuine()) continue;
            Finding.Severity sev = "CRITICAL".equals(v.severity()) ? CRITICAL : WARNING;
            String title = switch (v.kind()) {
                case SPINNING -> "Spinning thread (CPU-corroborated busy loop): " + shortName(st.name());
                case BLOCKED_CHAIN -> "Thread blocked on the same monitor for " + st.runLength()
                        + " consecutive dumps: " + shortName(st.name());
                default -> "Thread frozen for " + st.runLength() + " consecutive dumps: " + shortName(st.name());
            };
            String rec = switch (v.kind()) {
                case SPINNING -> "This is the signature of an infinite loop or busy-wait. The frozen frames "
                        + "point at the looping code - profile or fix that path. If it also holds a lock, "
                        + "every waiter is starving behind a spinning core.";
                case BLOCKED_CHAIN -> "Follow the lock to its holder in the blocker tree; shrinking the "
                        + "holder's critical section or fixing its blocking call releases this whole chain.";
                default -> "The frozen frames below show exactly where it sits. If the top frame is a "
                        + "socket/JDBC read, add a timeout on that call; if it is a computation, profile it.";
            };
            out.add(base(v, "stuck-thread", sev, title,
                    "\"" + st.name() + "\" shows the identical top-" + ctx.options().fingerprintDepth
                            + "-frame stack in dumps " + st.fromDump() + ".." + st.toDump() + " while "
                            + String.join("/", st.states()) + ". " + v.why() + ".",
                    rec));
        }
        return out;
    }

    private Finding base(StuckClassifier.Verdict v, String id, Finding.Severity sev,
                         String title, String detail, String rec) {
        StuckThreadDetector.Stuck st = v.stuck();
        Finding f = new Finding(id, sev, title, detail, rec)
                .evidence("thread", st.name())
                .evidence("dumps", st.fromDump() + ".." + st.toDump())
                .evidence("states", st.states())
                .evidence("confidence", v.confidence())
                .evidence("whyNotFalsePositive", v.why());
        if (st.cpuDeltaMillis() != null) f.evidence("cpuDeltaMillis", st.cpuDeltaMillis());
        if (st.wallClockSeconds() != null) f.evidence("wallClockSeconds", st.wallClockSeconds());
        if (v.victims() > 0) f.evidence("victims", v.victims());
        f.evidence("frames", st.frozenFrames().subList(0, Math.min(12, st.frozenFrames().size())));
        return f;
    }

    private String shortName(String name) {
        return name.length() > 60 ? name.substring(0, 57) + "..." : name;
    }
}



/** RUNNABLE threads pinned in blocking socket reads - the JVM cannot see a network timeout that isn't set. */
final class NetworkHangPattern implements Pattern {
    private static final String[] SOCKET_FRAMES = {
            "java.net.SocketInputStream.socketRead0",
            "java.net.SocketInputStream.socketRead",
            "sun.nio.ch.NioSocketImpl.park",
            "sun.security.ssl.SSLSocketInputRecord.read",
            "java.net.SocketTimeoutException", // never a frame, harmless
    };

    @Override public List<Finding> detect(PatternContext ctx) {
        // strongest signal: the same thread frozen in a socket read across dumps.
        // Idle/housekeeping verdicts are excluded (selector and accept loops live in
        // socket frames by design); NATIVE_WAIT and genuine verdicts qualify.
        List<String> frozen = new ArrayList<>();
        for (StuckClassifier.Verdict v : ctx.stuckVerdicts()) {
            if (v.kind() == StuckClassifier.Kind.IDLE
                    || v.kind() == StuckClassifier.Kind.HOUSEKEEPING
                    || v.kind() == StuckClassifier.Kind.DISCARDED) continue;
            StuckThreadDetector.Stuck st = v.stuck();
            if (!st.frozenFrames().isEmpty() && containsSocketRead(st.frozenFrames())) frozen.add(st.name());
        }
        int worst = 0, worstDump = -1;
        List<Frames.Match> worstMatches = List.of();
        for (int i = 0; i < ctx.series().size(); i++) {
            List<Frames.Match> m = new ArrayList<>();
            for (ThreadInfo t : ctx.series().get(i).javaThreads()) {
                if (t.state() == ThreadState.RUNNABLE && Frames.topFrames(t, 4, SOCKET_FRAMES)) {
                    m.add(new Frames.Match(t, t.frames().get(0).raw()));
                }
            }
            if (m.size() > worst) { worst = m.size(); worstDump = i; worstMatches = m; }
        }
        if (worst == 0 && frozen.isEmpty()) return List.of();
        // Rule 5: CRITICAL needs demonstrable impact - a frozen socket read on a thread the
        // container itself marked stuck, or a large share of workers pinned at once.
        boolean stuckMarked = frozen.isEmpty() && ctx.series().size() > 0 ? false
                : ctx.series().dumps().stream().flatMap(d -> d.threads().stream())
                    .filter(t -> PoolGrouper.isStuckMarked(t.name()))
                    .anyMatch(t -> frozen.contains(
                            com.tda.core.analysis.series.SeriesIndex.normalizedName(t.name())));
        boolean severe = stuckMarked || worst >= ctx.options().criticalVictims;
        StringBuilder detail = new StringBuilder();
        if (worst > 0) {
            detail.append("Dump ").append(worstDump).append(" has ").append(worst)
                    .append(" RUNNABLE thread(s) inside a blocking socket read (socketRead0 and friends). ");
        }
        if (!frozen.isEmpty()) {
            detail.append(frozen.size()).append(" of them show the identical socket-read stack across ")
                    .append("consecutive dumps - the remote endpoint is not answering and no read timeout ")
                    .append("is cutting the call off.");
        } else {
            detail.append("A thread that stays in socketRead0 across dumps indicates a missing read timeout.");
        }
        Finding.Severity sev = severe ? CRITICAL : (frozen.isEmpty() ? INFO : WARNING);
        return List.of(new Finding("network-hang", sev,
                "Threads pinned in blocking socket reads" + (frozen.isEmpty() ? "" : " across dumps"),
                detail.toString(),
                "Set explicit read timeouts on every outbound call: JDBC (oracle.net.READ_TIMEOUT / "
                        + "socketTimeout), HTTP clients (connect + read timeout), JMS/MQ receive timeouts. "
                        + "Verify firewall idle-connection reaping (dead connections that never RST show "
                        + "exactly this signature). TCP keepalive alone is not enough.")
                .evidence("dump", worstDump)
                .evidence("runnableInSocketRead", worst)
                .evidence("frozenAcrossDumps", frozen)
                .evidence("threads", Frames.names(worstMatches, 15))
                .evidence("confidence", frozen.isEmpty() ? "low" : "high")
                .evidence("whyNotFalsePositive", frozen.isEmpty()
                        ? "single-dump snapshot only - a socket read can be momentary; treat as a hint"
                        : "socket-read stacks (not accept/selector idle loops - those are excluded) "
                          + "unchanged across consecutive dumps mean the remote end is not answering"));
    }

    private boolean containsSocketRead(List<String> frames) {
        int n = Math.min(4, frames.size());
        for (int i = 0; i < n; i++) {
            if (frames.get(i).contains("socketRead") || frames.get(i).contains("NioSocketImpl.park")) return true;
        }
        return false;
    }
}


/** Finalizer thread not idle-waiting = a finalization backlog is forming (GC-adjacent indicator). */
final class FinalizerBacklogPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        List<Integer> busyDumps = new ArrayList<>();
        String state = "";
        String frame = "";
        for (int i = 0; i < ctx.series().size(); i++) {
            ThreadDump d = ctx.series().get(i);
            ThreadInfo fin = d.findByName("Finalizer");
            if (fin == null || fin.frames().isEmpty()) continue;
            boolean idle = fin.state() == ThreadState.WAITING
                    && Frames.topFrames(fin, 4, "java.lang.ref.ReferenceQueue.remove",
                            "java.lang.Object.wait");
            if (!idle) {
                busyDumps.add(i);
                state = fin.state().name();
                frame = fin.frames().get(0).raw();
            }
        }
        if (busyDumps.isEmpty()) return List.of();
        boolean persistent = busyDumps.size() >= Math.max(2, ctx.series().size() / 2);
        return List.of(new Finding("finalizer-backlog", persistent ? WARNING : INFO,
                "Finalizer thread busy in " + busyDumps.size() + " of " + ctx.series().size() + " dump(s)",
                "The Finalizer thread is normally WAITING on its ReferenceQueue. Here it is " + state
                        + " in `" + frame + "`. Objects with finalize() are piling up faster than one "
                        + "thread can process them; the backlog keeps them (and everything they reference) "
                        + "alive, inflating the heap and lengthening GC pauses.",
                "Find what allocates finalizable objects on the hot path (often unclosed "
                        + "streams/sockets/JDBC resources whose classes finalize as a safety net). Close "
                        + "resources explicitly (try-with-resources) or switch to java.lang.ref.Cleaner. "
                        + "Capture a heap histogram (jmap -histo) and look for java.lang.ref.Finalizer counts.")
                .evidence("dumps", busyDumps)
                .evidence("finalizerState", state)
                .evidence("frame", frame)
                .evidence("confidence", persistent ? "high" : "low")
                .evidence("whyNotFalsePositive", "the Finalizer thread's idle state is WAITING on "
                        + "its ReferenceQueue; any other persistent state means finalization work "
                        + "is queuing"));
    }
}

/** The single thread whose lock release would unblock the most other threads. */
final class TopBlockerPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        String bestThread = null;
        int bestCount = 0, bestDump = -1, bestDirect = 0;
        for (int i = 0; i < ctx.series().size(); i++) {
            LockGraph g = ctx.graphs().get(i);
            Map<String, List<String>> direct = g.directVictims();
            for (Map.Entry<String, Integer> e : g.transitiveVictimCounts().entrySet()) {
                if (e.getValue() > bestCount) {
                    bestCount = e.getValue();
                    bestThread = e.getKey();
                    bestDump = i;
                    bestDirect = direct.getOrDefault(e.getKey(), List.of()).size();
                }
            }
        }
        if (bestThread == null || bestCount < 2) return List.of();
        LockGraph g = ctx.graphs().get(bestDump);
        ThreadInfo t = g.thread(bestThread);
        Finding f = new Finding("top-blocker",
                bestCount >= ctx.options().criticalVictims ? CRITICAL : WARNING,
                "Top blocker: \"" + bestThread + "\" starves " + bestCount + " thread(s)",
                "In dump " + bestDump + ", releasing the locks held by \"" + bestThread + "\" would "
                        + "directly unblock " + bestDirect + " thread(s) and transitively up to " + bestCount
                        + ". Everything else in the blocker tree hangs off this one thread.",
                "Look at what this thread is doing (its stack is the root of the blocker tree in the "
                        + "report). If it is itself waiting on I/O, fix that call's timeout; if it is "
                        + "computing inside a synchronized section, shrink the critical section or replace "
                        + "the lock with a concurrent data structure.")
                .evidence("dump", bestDump)
                .evidence("thread", bestThread)
                .evidence("directVictims", bestDirect)
                .evidence("transitiveVictims", bestCount)
                .evidence("confidence", "high")
                .evidence("whyNotFalsePositive", bestCount + " thread(s) are observably parked in the "
                        + "dump waiting on locks this thread holds - counted from the wait-for graph, "
                        + "not inferred");
        if (t != null && !t.frames().isEmpty()) {
            List<String> frames = new ArrayList<>();
            for (int i = 0; i < Math.min(8, t.frames().size()); i++) frames.add(t.frames().get(i).raw());
            f.evidence("frames", frames);
        }
        return List.of(f);
    }
}

/** Long or frequent stop-the-world windows from a supplied GC/safepoint log. */
final class GcPausePattern implements Pattern {
    static final double LONG_PAUSE_WARN_MS = 1000;
    static final double LONG_PAUSE_CRITICAL_MS = 5000;

    @Override public List<Finding> detect(PatternContext ctx) {
        var pauses = ctx.gcPauses();
        if (pauses.isEmpty()) return List.of();
        List<Finding> out = new ArrayList<>();

        var longest = pauses.stream()
                .filter(p -> p.durationMs() >= LONG_PAUSE_WARN_MS)
                .sorted((a, b) -> Double.compare(b.durationMs(), a.durationMs()))
                .limit(5).toList();
        if (!longest.isEmpty()) {
            var worst = longest.get(0);
            out.add(new Finding("long-gc-pause",
                    worst.durationMs() >= LONG_PAUSE_CRITICAL_MS ? CRITICAL : WARNING,
                    String.format("Long stop-the-world pause: %.0f ms (%s)",
                            worst.durationMs(), worst.cause()),
                    longest.size() + " pause(s) exceeded " + (long) LONG_PAUSE_WARN_MS + " ms during "
                            + "the capture window. Every application thread stands still for the "
                            + "entire pause - requests stall, timeouts fire, and frozen-looking "
                            + "threads in the dumps may simply be paused.",
                    "Tune for the collector in use (heap sizing, region sizes, "
                            + "-XX:MaxGCPauseMillis for G1) or move to a low-pause collector "
                            + "(G1 -> ZGC/Shenandoah). If the cause is a safepoint other than GC, "
                            + "find the requesting VM operation.")
                    .evidence("pauses", longest.stream().map(p -> Map.of(
                            "start", p.start().toString(),
                            "durationMs", p.durationMs(),
                            "cause", p.cause(), "kind", p.kind())).toList())
                    .evidence("confidence", "high")
                    .evidence("whyNotFalsePositive",
                            "pause durations are the JVM's own measurements from its GC log"));
        }

        var first = pauses.get(0).start();
        var last = pauses.get(pauses.size() - 1).end();
        double windowMs = Math.max(1, java.time.Duration.between(first, last).toMillis());
        double stoppedMs = pauses.stream().mapToDouble(GcLogParser.PauseWindow::durationMs).sum();
        double pct = 100.0 * stoppedMs / windowMs;
        if (pct >= 10.0 && pauses.size() >= 5) {
            out.add(new Finding("frequent-safepoints", WARNING,
                    String.format("Application stopped %.1f%% of the time (%d pauses)",
                            pct, pauses.size()),
                    String.format("Across the logged window the JVM spent %.0f ms of %.0f ms "
                            + "inside stop-the-world pauses. Throughput and latency both suffer "
                            + "before any single pause looks alarming.", stoppedMs, windowMs),
                    "Check allocation rate (frequent young GCs), humongous allocations on G1, "
                            + "explicit System.gc() calls, and non-GC safepoint causes "
                            + "(-Xlog:safepoint shows the requesting operation).")
                    .evidence("stoppedMs", Math.round(stoppedMs))
                    .evidence("windowMs", Math.round(windowMs))
                    .evidence("pauseCount", pauses.size())
                    .evidence("confidence", "high")
                    .evidence("whyNotFalsePositive",
                            "aggregated from the JVM's own pause accounting, not sampled"));
        }
        return out;
    }
}


/** Monotonic per-pool growth across the series - a thread leak in the making. */
final class ThreadLeakPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (PoolTrend.Trend t : ctx.poolTrends()) {
            if (!t.leakSuspect()) continue;
            out.add(new Finding("thread-leak", WARNING,
                    "Pool \"" + t.pool() + "\" grew every dump: " + t.counts(),
                    "The thread count of \"" + t.pool() + "\" rose monotonically across the series ("
                            + t.counts().get(0) + " → " + t.counts().get(t.counts().size() - 1)
                            + "). Pools that only ever grow usually mean tasks never finish (each new burst "
                            + "spawns threads that block forever) or code creates a new executor per request "
                            + "and never shuts it down.",
                    "Diff this pool's stacks between the first and last dump (they are matched in this "
                            + "report). If old threads all sit in the same frame, that call is the leak's "
                            + "root cause. Audit for ExecutorService instances created per request without "
                            + "shutdown(), and give pools a bounded maximum plus a rejection policy.")
                    .evidence("pool", t.pool())
                    .evidence("counts", t.counts())
                    .evidence("growth", t.growth())
                    .evidence("confidence", "medium")
                    .evidence("whyNotFalsePositive", "strictly monotonic growth across every dump in "
                            + "the series - normal pools shrink or plateau between snapshots"));
        }
        return out;
    }
}

/** INFO-only pool right-sizing hints from observed busy/idle utilization across the series. */
final class PoolSizingPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        List<Finding> out = new ArrayList<>();
        for (PatternContext.PoolUtil u : ctx.poolUtilization()) {
            if (ctx.series().size() < 2) break; // utilization needs a series
            if (u.avgBusyPct() >= 90 && u.blockedSeen() > 0) {
                out.add(new Finding("pool-sizing", INFO,
                        "Pool \"" + u.pool() + "\" ran " + Math.round(u.avgBusyPct())
                                + "% busy with blocked work - consider increasing",
                        "Across the series this pool averaged " + Math.round(u.avgBusyPct())
                                + "% busy at an observed size of " + u.maxSize() + ", while "
                                + u.blockedSeen() + " thread(s) sat BLOCKED behind its work. A "
                                + "hint, not a finding: verify against the pool's configured max.",
                        "If the configured max equals the observed size, raise it (or fix the "
                                + "downstream slowness that keeps workers busy).")
                        .evidence("pool", u.pool())
                        .evidence("avgBusyPct", Math.round(u.avgBusyPct()))
                        .evidence("observedMax", u.maxSize())
                        .evidence("confidence", "medium")
                        .evidence("whyNotFalsePositive",
                                "busy/idle is measured per dump from thread classification, "
                                + "not inferred"));
            } else if (u.avgBusyPct() <= 10 && u.maxSize() >= 20) {
                out.add(new Finding("pool-sizing", INFO,
                        "Pool \"" + u.pool() + "\" is " + Math.round(u.avgBusyPct())
                                + "% busy at size " + u.maxSize() + " - likely oversized",
                        "A hint, not a finding: " + u.maxSize() + " threads exist but on average "
                                + "only " + Math.round(u.avgBusyPct()) + "% do work. Each idle "
                                + "thread costs stack memory and scheduler load.",
                        "Shrink the pool (or its minimum) unless it is sized for a known burst.")
                        .evidence("pool", u.pool())
                        .evidence("avgBusyPct", Math.round(u.avgBusyPct()))
                        .evidence("observedMax", u.maxSize())
                        .evidence("confidence", "medium")
                        .evidence("whyNotFalsePositive",
                                "busy/idle is measured per dump from thread classification, "
                                + "not inferred"));
            }
        }
        return out;
    }
}
