package com.tda.core.analysis.pattern;

import com.tda.core.analysis.series.PersistentLockHolders;
import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.StuckThreadDetector;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.tda.core.analysis.pattern.Finding.Severity.CRITICAL;
import static com.tda.core.analysis.pattern.Finding.Severity.INFO;
import static com.tda.core.analysis.pattern.Finding.Severity.WARNING;

/** The built-in pattern library; runs every detector and returns findings ranked by severity. */
public final class PatternLibrary {

    private final List<Pattern> patterns = List.of(
            new DeadlockPattern(),
            new WebLogicStuckPattern(),
            new StuckThreadPattern(),
            new ConnectionPoolExhaustionPattern(),
            new SyncLoggingPattern(),
            new NetworkHangPattern(),
            new ClassloaderContentionPattern(),
            new FinalizerBacklogPattern(),
            new TopBlockerPattern(),
            new ThreadLeakPattern());

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
                        .evidence("source", c.source()));
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
                    .evidence("dumpsSeen", stuckDumps.values().stream().map(List::size).toList()));
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

/** Fingerprint-based long-runner detection (series analysis) promoted to findings. */
final class StuckThreadPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        if (ctx.stuckThreads().isEmpty() || ctx.series().size() < 2) return List.of();
        List<Finding> out = new ArrayList<>();
        for (StuckThreadDetector.Stuck st : ctx.stuckThreads()) {
            boolean wholeSeries = st.runLength() >= ctx.series().size();
            out.add(new Finding("stuck-thread", wholeSeries ? CRITICAL : WARNING,
                    "Thread frozen for " + st.runLength() + " consecutive dumps: " + shortName(st.name()),
                    "\"" + st.name() + "\" shows the identical top-" + ctx.options().fingerprintDepth
                            + "-frame stack in dumps " + st.fromDump() + ".." + st.toDump()
                            + " while " + String.join("/", st.states())
                            + ". A healthy worker thread changes its stack between dumps taken seconds apart.",
                    "The frozen frames below show exactly where it sits. If the top frame is a socket/JDBC "
                            + "read, add a timeout on that call. If it is BLOCKED, follow the lock to the "
                            + "holder (see the blocker tree). If it is a computation loop, profile that code path.")
                    .evidence("thread", st.name())
                    .evidence("fromDump", st.fromDump())
                    .evidence("toDump", st.toDump())
                    .evidence("states", st.states())
                    .evidence("frames", st.frozenFrames().subList(0, Math.min(12, st.frozenFrames().size()))));
        }
        return out;
    }

    private String shortName(String name) {
        return name.length() > 60 ? name.substring(0, 57) + "..." : name;
    }
}

/** Many threads waiting inside a connection-pool borrow call = the pool is exhausted. */
final class ConnectionPoolExhaustionPattern implements Pattern {
    private static final String[] BORROW_FRAMES = {
            "com.zaxxer.hikari.util.ConcurrentBag.borrow",
            "com.zaxxer.hikari.pool.HikariPool.getConnection",
            "oracle.ucp.jdbc.PoolDataSourceImpl.getConnection",
            "oracle.ucp.common.UniversalConnectionPoolBase.borrowConnection",
            "weblogic.jdbc.common.internal.ConnectionPool.reserve",
            "weblogic.common.resourcepool.ResourcePoolImpl.reserveResource",
            "org.apache.commons.dbcp2.PoolingDataSource.getConnection",
            "org.apache.commons.pool2.impl.GenericObjectPool.borrowObject",
            "org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection",
            "com.mchange.v2.resourcepool.BasicResourcePool.awaitAvailable",
    };
    private static final Set<ThreadState> WAITING_STATES =
            Set.of(ThreadState.WAITING, ThreadState.TIMED_WAITING, ThreadState.BLOCKED);

    @Override public List<Finding> detect(PatternContext ctx) {
        int worst = 0, worstDump = -1;
        List<Frames.Match> worstMatches = List.of();
        for (int i = 0; i < ctx.series().size(); i++) {
            List<Frames.Match> m = Frames.scan(ctx.series().get(i), WAITING_STATES, BORROW_FRAMES);
            if (m.size() > worst) { worst = m.size(); worstDump = i; worstMatches = m; }
        }
        if (worst < 3) return List.of();
        return List.of(new Finding("connection-pool-exhaustion", worst >= 10 ? CRITICAL : WARNING,
                worst + " threads waiting for a database connection",
                "In dump " + worstDump + ", " + worst + " threads sit inside a connection-pool borrow call "
                        + "(HikariCP / UCP / WebLogic JDBC / DBCP). The pool has no free connections: either "
                        + "it is undersized for the load, connections are leaking, or every connection is "
                        + "tied up in slow queries.",
                "Check what the threads that DO hold connections are executing (often stuck in socketRead0 "
                        + "on a slow query - see the network-hang finding if present). Review pool max size "
                        + "vs. concurrent workers, enable leak detection (e.g. HikariCP leakDetectionThreshold, "
                        + "UCP InactiveConnectionTimeout, WebLogic Inactive Connection Timeout + Profile "
                        + "Connection Leak), and set statement/query timeouts so one slow query cannot pin a "
                        + "connection forever.")
                .evidence("dump", worstDump)
                .evidence("waitingThreads", worst)
                .evidence("threads", Frames.names(worstMatches, 15))
                .evidence("frame", worstMatches.isEmpty() ? "" : worstMatches.get(0).matchedFrame()));
    }
}

/** Many threads BLOCKED on a logging framework's synchronized appender. */
final class SyncLoggingPattern implements Pattern {
    private static final String[] LOG_FRAMES = {
            "org.apache.log4j.Category.callAppenders",
            "org.apache.log4j.AppenderSkeleton.doAppend",
            "org.apache.logging.log4j.core.appender.OutputStreamManager",
            "ch.qos.logback.core.OutputStreamAppender",
            "ch.qos.logback.core.AppenderBase.doAppend",
            "java.util.logging.Logger.log",
            "java.util.logging.StreamHandler.publish",
    };

    @Override public List<Finding> detect(PatternContext ctx) {
        int worst = 0, worstDump = -1;
        List<Frames.Match> worstMatches = List.of();
        for (int i = 0; i < ctx.series().size(); i++) {
            List<Frames.Match> m = Frames.scan(ctx.series().get(i), Set.of(ThreadState.BLOCKED), LOG_FRAMES);
            if (m.size() > worst) { worst = m.size(); worstDump = i; worstMatches = m; }
        }
        if (worst < 3) return List.of();
        return List.of(new Finding("sync-logging-bottleneck", worst >= 10 ? CRITICAL : WARNING,
                worst + " threads BLOCKED on synchronized logging",
                "In dump " + worstDump + ", " + worst + " threads are BLOCKED inside the logging framework "
                        + "(Logger/Category/Appender). Synchronous appenders serialize every log call through "
                        + "one lock; under load or with slow I/O (console, NFS, disk pressure) the whole "
                        + "worker pool queues behind the thread currently writing.",
                "Switch to async logging: Log4j2 AsyncAppender/AsyncLogger (LMAX disruptor), Logback "
                        + "AsyncAppender, or reduce log volume at INFO level on hot paths. Never log to "
                        + "console in production WebLogic/Tomcat - stdout is often the slowest sink.")
                .evidence("dump", worstDump)
                .evidence("blockedThreads", worst)
                .evidence("threads", Frames.names(worstMatches, 15))
                .evidence("frame", worstMatches.isEmpty() ? "" : worstMatches.get(0).matchedFrame()));
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
        // strongest signal: the same thread frozen in a socket read across dumps
        List<String> frozen = new ArrayList<>();
        for (StuckThreadDetector.Stuck st : ctx.stuckThreads()) {
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
        boolean severe = !frozen.isEmpty() || worst >= 5;
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
        return List.of(new Finding("network-hang", severe ? CRITICAL : INFO,
                "Threads pinned in blocking socket reads" + (frozen.isEmpty() ? "" : " across dumps"),
                detail.toString(),
                "Set explicit read timeouts on every outbound call: JDBC (oracle.net.READ_TIMEOUT / "
                        + "socketTimeout), HTTP clients (connect + read timeout), JMS/MQ receive timeouts. "
                        + "Verify firewall idle-connection reaping (dead connections that never RST show "
                        + "exactly this signature). TCP keepalive alone is not enough.")
                .evidence("dump", worstDump)
                .evidence("runnableInSocketRead", worst)
                .evidence("frozenAcrossDumps", frozen)
                .evidence("threads", Frames.names(worstMatches, 15)));
    }

    private boolean containsSocketRead(List<String> frames) {
        int n = Math.min(4, frames.size());
        for (int i = 0; i < n; i++) {
            if (frames.get(i).contains("socketRead") || frames.get(i).contains("NioSocketImpl.park")) return true;
        }
        return false;
    }
}

/** Many threads BLOCKED in ClassLoader.loadClass. */
final class ClassloaderContentionPattern implements Pattern {
    @Override public List<Finding> detect(PatternContext ctx) {
        int worst = 0, worstDump = -1;
        List<Frames.Match> worstMatches = List.of();
        for (int i = 0; i < ctx.series().size(); i++) {
            List<Frames.Match> m = Frames.scan(ctx.series().get(i), Set.of(ThreadState.BLOCKED),
                    "java.lang.ClassLoader.loadClass", ".loadClass");
            if (m.size() > worst) { worst = m.size(); worstDump = i; worstMatches = m; }
        }
        if (worst < 3) return List.of();
        return List.of(new Finding("classloader-contention", WARNING,
                worst + " threads BLOCKED in class loading",
                "In dump " + worstDump + ", " + worst + " threads contend on classloader locks in "
                        + "loadClass. Typical causes: first requests after deployment/restart loading classes "
                        + "lazily under full traffic, non-parallel-capable custom classloaders, or code that "
                        + "calls Class.forName per request.",
                "Warm the application before admitting traffic (startup class-loading, a warm-up request "
                        + "set). Make custom classloaders parallel-capable (registerAsParallelCapable). Cache "
                        + "Class.forName / reflection lookups instead of resolving per request.")
                .evidence("dump", worstDump)
                .evidence("blockedThreads", worst)
                .evidence("threads", Frames.names(worstMatches, 15)));
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
                .evidence("frame", frame));
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
        Finding f = new Finding("top-blocker", bestCount >= 10 ? CRITICAL : WARNING,
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
                .evidence("transitiveVictims", bestCount);
        if (t != null && !t.frames().isEmpty()) {
            List<String> frames = new ArrayList<>();
            for (int i = 0; i < Math.min(8, t.frames().size()); i++) frames.add(t.frames().get(i).raw());
            f.evidence("frames", frames);
        }
        return List.of(f);
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
                    .evidence("growth", t.growth()));
        }
        return out;
    }
}
