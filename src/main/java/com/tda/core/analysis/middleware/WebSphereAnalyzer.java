package com.tda.core.analysis.middleware;

import com.tda.core.analysis.pattern.Finding;
import com.tda.core.analysis.pattern.Pattern;
import com.tda.core.analysis.pattern.PatternContext;
import com.tda.core.model.ThreadDump;

import java.util.ArrayList;
import java.util.List;

import static com.tda.core.analysis.pattern.Finding.Severity.CRITICAL;
import static com.tda.core.analysis.pattern.Finding.Severity.WARNING;

/**
 * WebSphere-specific health checks (traditional WAS and Liberty), gated on
 * {@link MiddlewareDetector}:
 * <ul>
 *   <li><b>WebContainer saturation</b> - every {@code WebContainer : N} thread busy. WAS's
 *       own hung-thread detection (WSVR0605W) only fires after 10 minutes by default; a
 *       fully-busy pool with blocked members is the same incident, seen earlier.</li>
 *   <li><b>Liberty default executor saturation</b> - {@code Default Executor-thread-N} all
 *       busy with BLOCKED members. Liberty auto-tunes the executor size, so only blocked
 *       saturation (growth cannot help) is reported.</li>
 *   <li><b>OOM-triggered javacore</b> - a javacore whose {@code 1TISIGINFO} says the dump
 *       was written on OutOfMemoryError: thread analysis is secondary evidence then, and
 *       the report should say so up front.</li>
 * </ul>
 */
public final class WebSphereAnalyzer implements Pattern {

    static final java.util.regex.Pattern WEBCONTAINER =
            java.util.regex.Pattern.compile("^WebContainer : \\d+$");
    static final java.util.regex.Pattern LIBERTY_EXEC =
            java.util.regex.Pattern.compile("^Default Executor-thread-\\d+$");
    static final int MIN_POOL_FOR_SATURATION = 8;

    @Override public List<Finding> detect(PatternContext ctx) {
        MiddlewareDetector.Platform p = ctx.middleware().platform();
        boolean was = p == MiddlewareDetector.Platform.WEBSPHERE;
        boolean liberty = p == MiddlewareDetector.Platform.LIBERTY;
        if (!was && !liberty) return List.of();
        List<Finding> out = new ArrayList<>();
        if (was) out.addAll(webContainerSaturation(ctx));
        if (liberty) out.addAll(libertyExecutorSaturation(ctx));
        out.addAll(oomJavacore(ctx));
        return out;
    }

    private List<Finding> webContainerSaturation(PatternContext ctx) {
        List<PoolHealth.Snapshot> snaps = new ArrayList<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            PoolHealth.Snapshot s = PoolHealth.snapshot(ctx.series().get(i), i,
                    n -> WEBCONTAINER.matcher(n).matches(), ctx.classifier());
            if (s.total() > 0) snaps.add(s);
        }
        if (snaps.isEmpty()) return List.of();
        PoolHealth.Snapshot worst = PoolHealth.worst(snaps);
        if (worst.total() < MIN_POOL_FOR_SATURATION || !worst.saturated()) return List.of();
        boolean persistent = PoolHealth.saturatedThroughout(snaps);
        int maxBlocked = PoolHealth.maxBlocked(snaps);
        boolean severe = persistent || maxBlocked >= ctx.options().criticalVictims;
        return List.of(new Finding("websphere-webcontainer-saturation", severe ? CRITICAL : WARNING,
                "WebSphere WebContainer pool: every thread busy"
                        + (persistent ? " in every dump" : ""),
                "In dump " + worst.dumpIndex() + " all " + worst.total() + " WebContainer threads "
                        + "are working requests (none waiting on the BoundedBuffer for work), "
                        + maxBlocked + " BLOCKED. New HTTP requests queue in the transport channel; "
                        + "WAS itself only raises WSVR0605W hung-thread warnings after "
                        + "com.ibm.websphere.threadmonitor.threshold (default 600 s).",
                "Inspect the busy threads' stacks (usually all waiting on one backend or one "
                        + "monitor). Compare the observed size against the WebContainer pool's "
                        + "configured maximum in the admin console; if they match, the pool is "
                        + "exhausted - fix the slow dependency before raising the maximum. Take "
                        + "javacores 30 s apart (kill -3) so cross-dump analysis can pinpoint the "
                        + "stuck requests.")
                .evidence("dump", worst.dumpIndex())
                .evidence("threads", worst.total())
                .evidence("busy", worst.busy())
                .evidence("blocked", maxBlocked)
                .evidence("saturatedAllDumps", persistent)
                .evidence("busyThreads", worst.busyThreads())
                .evidence("confidence", persistent ? "high" : "medium")
                .evidence("whyNotFalsePositive", "threads parked in com.ibm.ws.util.BoundedBuffer."
                        + "waitGet_ count as idle via the idle-pattern knowledge base; only threads "
                        + "actually executing requests count as busy"));
    }

    private List<Finding> libertyExecutorSaturation(PatternContext ctx) {
        List<PoolHealth.Snapshot> snaps = new ArrayList<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            PoolHealth.Snapshot s = PoolHealth.snapshot(ctx.series().get(i), i,
                    n -> LIBERTY_EXEC.matcher(n).matches(), ctx.classifier());
            if (s.total() > 0) snaps.add(s);
        }
        if (snaps.isEmpty()) return List.of();
        PoolHealth.Snapshot worst = PoolHealth.worst(snaps);
        int maxBlocked = PoolHealth.maxBlocked(snaps);
        // Liberty grows the executor on demand - saturation only matters when growth cannot
        // help, i.e. a meaningful share of the workers are BLOCKED on the same thing.
        if (worst.total() < MIN_POOL_FOR_SATURATION || !worst.saturated() || maxBlocked == 0) {
            return List.of();
        }
        boolean severe = maxBlocked >= ctx.options().criticalVictims;
        return List.of(new Finding("liberty-executor-saturation", severe ? CRITICAL : WARNING,
                "Liberty default executor: all " + worst.total() + " threads busy, "
                        + maxBlocked + " BLOCKED",
                "Liberty's self-tuning executor normally grows past a busy spike; a fully busy pool "
                        + "with BLOCKED members means added threads would only pile onto the same "
                        + "contended resource. Dump " + worst.dumpIndex() + " shows " + worst.busy()
                        + "/" + worst.total() + " busy.",
                "Follow the BLOCKED workers to the monitor holder in the blocker tree, or check "
                        + "whether every busy worker waits on the same backend. coreThreads/maxThreads "
                        + "overrides in server.xml only help when workers are doing useful work.")
                .evidence("dump", worst.dumpIndex())
                .evidence("threads", worst.total())
                .evidence("busy", worst.busy())
                .evidence("blocked", maxBlocked)
                .evidence("busyThreads", worst.busyThreads())
                .evidence("confidence", "medium")
                .evidence("whyNotFalsePositive", "Liberty executor threads waiting for work are "
                        + "idle-classified; blocked saturation cannot be fixed by the executor's "
                        + "own auto-tuning"));
    }

    private List<Finding> oomJavacore(PatternContext ctx) {
        for (int i = 0; i < ctx.series().size(); i++) {
            ThreadDump d = ctx.series().get(i);
            String reason = d.dumpReason();
            if (reason != null && (reason.contains("OutOfMemoryError")
                    || reason.contains("systhrow") && reason.contains("OutOfMemory"))) {
                return List.of(new Finding("javacore-oom-trigger", CRITICAL,
                        "This javacore was written because of an OutOfMemoryError",
                        "Dump " + i + " (" + d.sourceName() + ") records dump event: " + reason
                                + ". Thread states in an OOM javacore describe the victim moment, "
                                + "not necessarily the cause - allocation-heavy threads and "
                                + "everything blocked behind GC are expected.",
                        "Analyze the matching heapdump.phd / system core for the leak (IBM MAT / "
                                + "Eclipse MAT). Use this thread analysis to identify what was "
                                + "running at the OOM instant and whether a request storm or cache "
                                + "growth preceded it.")
                        .evidence("dump", i)
                        .evidence("event", reason)
                        .evidence("confidence", "high")
                        .evidence("whyNotFalsePositive",
                                "the dump reason is recorded by the JVM itself in 1TISIGINFO"));
            }
        }
        return List.of();
    }
}
