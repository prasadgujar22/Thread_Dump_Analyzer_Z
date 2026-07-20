package com.tda.core.analysis.middleware;

import com.tda.core.analysis.pattern.Finding;
import com.tda.core.analysis.pattern.Pattern;
import com.tda.core.analysis.pattern.PatternContext;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

import static com.tda.core.analysis.pattern.Finding.Severity.CRITICAL;
import static com.tda.core.analysis.pattern.Finding.Severity.WARNING;

/**
 * WebLogic-specific health checks, gated on {@link MiddlewareDetector} so they never fire
 * on other servers. Complements the existing {@code [STUCK]}/{@code [HOGGING]} pattern:
 * <ul>
 *   <li><b>Self-tuning pool starvation</b> - every execute thread of a queue is busy with
 *       zero STANDBY reserve. WebLogic only marks a thread [STUCK] after StuckThreadMaxTime
 *       (default 600 s); a fully-busy pool is the incident <em>before</em> WLS says so.</li>
 *   <li><b>Socket-muxer health</b> - the muxer threads read every incoming socket. Muxers
 *       BLOCKED (or absent while the server clearly runs WebLogic) mean the front end stops
 *       accepting/reading requests no matter how healthy the execute queues look.</li>
 * </ul>
 */
public final class WebLogicAnalyzer implements Pattern {

    static final java.util.regex.Pattern QUEUE = java.util.regex.Pattern.compile(
            "^(?:\\[(?:STUCK|ACTIVE|STANDBY|HOGGING)] )?ExecuteThread:? '?\\d+'? for queue: '(.+?)'.*");
    private static final String MUXER_QUEUE = "weblogic.socket.Muxer";
    /** Below this size a fully-busy queue is normal burst behavior, not starvation. */
    static final int MIN_POOL_FOR_SATURATION = 8;

    static String queueOf(String threadName) {
        Matcher m = QUEUE.matcher(threadName);
        return m.matches() ? m.group(1) : null;
    }

    @Override public List<Finding> detect(PatternContext ctx) {
        if (ctx.middleware().platform() != MiddlewareDetector.Platform.WEBLOGIC) return List.of();
        List<Finding> out = new ArrayList<>();
        out.addAll(poolStarvation(ctx));
        out.addAll(muxerHealth(ctx));
        return out;
    }

    private List<Finding> poolStarvation(PatternContext ctx) {
        // queue -> snapshots per dump
        Map<String, List<PoolHealth.Snapshot>> byQueue = new LinkedHashMap<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            ThreadDump d = ctx.series().get(i);
            List<String> queues = new ArrayList<>();
            for (ThreadInfo t : d.threads()) {
                String q = queueOf(t.name());
                if (q != null && !MUXER_QUEUE.equals(q) && !queues.contains(q)) queues.add(q);
            }
            for (String q : queues) {
                byQueue.computeIfAbsent(q, k -> new ArrayList<>())
                        .add(PoolHealth.snapshot(d, i,
                                n -> q.equals(queueOf(n)), ctx.classifier()));
            }
        }
        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, List<PoolHealth.Snapshot>> e : byQueue.entrySet()) {
            List<PoolHealth.Snapshot> snaps = e.getValue();
            PoolHealth.Snapshot worst = PoolHealth.worst(snaps);
            if (worst.total() < MIN_POOL_FOR_SATURATION || !worst.saturated()) continue;
            boolean persistent = PoolHealth.saturatedThroughout(snaps);
            int maxBlocked = PoolHealth.maxBlocked(snaps);
            boolean severe = persistent || maxBlocked >= ctx.options().criticalVictims;
            out.add(new Finding("weblogic-thread-starvation", severe ? CRITICAL : WARNING,
                    "WebLogic queue '" + e.getKey() + "' has no free execute threads"
                            + (persistent ? " in any dump" : ""),
                    "In dump " + worst.dumpIndex() + " all " + worst.total() + " execute threads of "
                            + "queue '" + e.getKey() + "' are working requests (0 STANDBY, 0 idle), "
                            + maxBlocked + " of them BLOCKED. New requests queue up and the server "
                            + "will start declaring [STUCK] threads once StuckThreadMaxTime elapses - "
                            + "this finding fires before WebLogic's own 600 s verdict.",
                    "Check what the busy threads are doing (stacks in this report): a common cause is "
                            + "every worker waiting on one slow backend. Raise the work manager's "
                            + "max-threads-constraint only if the backend has headroom; otherwise fix the "
                            + "backend or add timeouts. Watch ThreadPoolRuntime PendingUserRequestCount "
                            + "to confirm queueing.")
                    .evidence("queue", e.getKey())
                    .evidence("dump", worst.dumpIndex())
                    .evidence("threads", worst.total())
                    .evidence("busy", worst.busy())
                    .evidence("blocked", maxBlocked)
                    .evidence("saturatedAllDumps", persistent)
                    .evidence("busyThreads", worst.busyThreads())
                    .evidence("confidence", persistent ? "high" : "medium")
                    .evidence("whyNotFalsePositive", "busy/idle is measured per thread from the "
                            + "idle-pattern knowledge base (waitForRequest and STANDBY threads count "
                            + "as free), not guessed from thread counts"));
        }
        return out;
    }

    private List<Finding> muxerHealth(PatternContext ctx) {
        int worstDump = -1, worstBlocked = 0, muxerCount = 0;
        List<String> blockedNames = List.of();
        for (int i = 0; i < ctx.series().size(); i++) {
            int total = 0, blocked = 0;
            List<String> names = new ArrayList<>();
            for (ThreadInfo t : ctx.series().get(i).threads()) {
                boolean muxer = MUXER_QUEUE.equals(queueOf(t.name()))
                        || t.frames().stream().anyMatch(f ->
                                f.classFqn().startsWith("weblogic.socket.") && f.classFqn().contains("Muxer"));
                if (!muxer) continue;
                total++;
                if (t.state() == ThreadState.BLOCKED) { blocked++; names.add(t.name()); }
            }
            muxerCount = Math.max(muxerCount, total);
            if (blocked > worstBlocked) { worstBlocked = blocked; worstDump = i; blockedNames = names; }
        }
        if (muxerCount == 0 || worstBlocked == 0) return List.of();
        boolean allBlocked = worstBlocked >= muxerCount;
        return List.of(new Finding("weblogic-muxer-blocked", allBlocked ? CRITICAL : WARNING,
                allBlocked ? "All " + muxerCount + " WebLogic socket muxer threads are BLOCKED"
                        : worstBlocked + " of " + muxerCount + " WebLogic socket muxer threads BLOCKED",
                "The socket muxer threads multiplex every incoming connection. In dump " + worstDump
                        + ", " + worstBlocked + " muxer thread(s) sit BLOCKED on a Java monitor instead "
                        + "of polling sockets" + (allBlocked
                        ? " - the server has effectively stopped reading network input; clients see "
                          + "hangs and connection timeouts even though execute threads may look free."
                        : " - front-end capacity is reduced."),
                "Follow the muxer threads' monitors in the blocker tree to the holder. Muxers must "
                        + "never run application code; a lock shared between a muxer and application "
                        + "threads (logging is the classic offender) is the root cause.")
                .evidence("dump", worstDump)
                .evidence("muxerThreads", muxerCount)
                .evidence("blocked", worstBlocked)
                .evidence("blockedThreads", blockedNames)
                .evidence("confidence", "high")
                .evidence("whyNotFalsePositive", "healthy muxers poll in weblogic.socket.*Muxer."
                        + "processSockets (an idle pattern) - BLOCKED is never their normal state"));
    }
}
