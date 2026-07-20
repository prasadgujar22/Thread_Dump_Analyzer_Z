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
 * Tomcat-specific health checks (also fire for embedded Tomcat in Spring Boot), gated on
 * {@link MiddlewareDetector}:
 * <ul>
 *   <li><b>Connector exhaustion</b> - every {@code <connector>-exec-N} worker of a connector
 *       is busy. At maxThreads, further requests wait in the accept queue up to acceptCount
 *       and then get connection refused; nothing in the JVM marks this, so the dump is the
 *       only witness.</li>
 *   <li><b>Poller/acceptor health</b> - the connector's Poller and Acceptor threads must be
 *       alive and not BLOCKED, or no request reaches the exec pool at all.</li>
 *   <li><b>Background processor wedged</b> - {@code ContainerBackgroundProcessor} runs session
 *       expiry, webapp reload scanning, and cache eviction; a BLOCKED or missing background
 *       processor silently breaks all three.</li>
 * </ul>
 */
public final class TomcatAnalyzer implements Pattern {

    static final java.util.regex.Pattern EXEC = java.util.regex.Pattern.compile(
            "^((?:http|https|ajp)-[\\w.-]+)-exec-\\d+$");
    private static final java.util.regex.Pattern SUPPORT = java.util.regex.Pattern.compile(
            "^((?:http|https|ajp)-[\\w.-]+)-(Poller|Acceptor|ClientPoller)(?:-\\d+)?$");
    static final int MIN_POOL_FOR_SATURATION = 8;

    static String connectorOf(String threadName) {
        Matcher m = EXEC.matcher(threadName);
        return m.matches() ? m.group(1) : null;
    }

    @Override public List<Finding> detect(PatternContext ctx) {
        if (ctx.middleware().platform() != MiddlewareDetector.Platform.TOMCAT) return List.of();
        List<Finding> out = new ArrayList<>();
        out.addAll(connectorExhaustion(ctx));
        out.addAll(supportThreadHealth(ctx));
        out.addAll(backgroundProcessor(ctx));
        return out;
    }

    private List<Finding> connectorExhaustion(PatternContext ctx) {
        Map<String, List<PoolHealth.Snapshot>> byConnector = new LinkedHashMap<>();
        for (int i = 0; i < ctx.series().size(); i++) {
            ThreadDump d = ctx.series().get(i);
            List<String> connectors = new ArrayList<>();
            for (ThreadInfo t : d.threads()) {
                String c = connectorOf(t.name());
                if (c != null && !connectors.contains(c)) connectors.add(c);
            }
            for (String c : connectors) {
                byConnector.computeIfAbsent(c, k -> new ArrayList<>())
                        .add(PoolHealth.snapshot(d, i, n -> c.equals(connectorOf(n)), ctx.classifier()));
            }
        }
        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, List<PoolHealth.Snapshot>> e : byConnector.entrySet()) {
            List<PoolHealth.Snapshot> snaps = e.getValue();
            PoolHealth.Snapshot worst = PoolHealth.worst(snaps);
            if (worst.total() < MIN_POOL_FOR_SATURATION || !worst.saturated()) continue;
            boolean persistent = PoolHealth.saturatedThroughout(snaps);
            int maxBlocked = PoolHealth.maxBlocked(snaps);
            boolean severe = persistent || maxBlocked >= ctx.options().criticalVictims;
            out.add(new Finding("tomcat-connector-exhaustion", severe ? CRITICAL : WARNING,
                    "Tomcat connector " + e.getKey() + ": every exec thread busy"
                            + (persistent ? " in every dump" : ""),
                    "In dump " + worst.dumpIndex() + " all " + worst.total() + " workers of "
                            + e.getKey() + " are processing requests (0 idle in the TaskQueue), "
                            + maxBlocked + " of them BLOCKED. If " + worst.total() + " equals the "
                            + "connector's maxThreads, new requests wait in the accept queue "
                            + "(acceptCount, default 100) and then fail to connect - the classic "
                            + "'Tomcat stopped responding' incident with a healthy-looking JVM.",
                    "Check the busy workers' stacks: exhaustion is almost always every worker stuck "
                            + "on the same downstream (JDBC pool, HTTP call, lock) - fix that before "
                            + "raising maxThreads. Confirm the configured maxThreads for this connector; "
                            + "if workers are genuinely doing useful work, raise maxThreads and monitor "
                            + "the executor's queue.")
                    .evidence("connector", e.getKey())
                    .evidence("dump", worst.dumpIndex())
                    .evidence("threads", worst.total())
                    .evidence("busy", worst.busy())
                    .evidence("blocked", maxBlocked)
                    .evidence("saturatedAllDumps", persistent)
                    .evidence("busyThreads", worst.busyThreads())
                    .evidence("confidence", persistent ? "high" : "medium")
                    .evidence("whyNotFalsePositive", "workers parked in TaskQueue.take count as "
                            + "idle via the idle-pattern knowledge base; only threads actually "
                            + "executing requests count as busy"));
        }
        return out;
    }

    private List<Finding> supportThreadHealth(PatternContext ctx) {
        // connector -> role -> blocked-in-dump indexes
        Map<String, List<String>> blockedByConnector = new LinkedHashMap<>();
        int atDump = -1;
        for (int i = 0; i < ctx.series().size(); i++) {
            for (ThreadInfo t : ctx.series().get(i).threads()) {
                Matcher m = SUPPORT.matcher(t.name());
                if (!m.matches() || t.state() != ThreadState.BLOCKED) continue;
                blockedByConnector.computeIfAbsent(m.group(1), k -> new ArrayList<>()).add(t.name());
                atDump = i;
            }
        }
        if (blockedByConnector.isEmpty()) return List.of();
        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : blockedByConnector.entrySet()) {
            out.add(new Finding("tomcat-poller-blocked", CRITICAL,
                    "Tomcat connector " + e.getKey() + ": Poller/Acceptor thread BLOCKED",
                    "Thread(s) " + e.getValue() + " are BLOCKED on a Java monitor. The Poller "
                            + "dispatches ready sockets and the Acceptor accepts new connections; while "
                            + "either is BLOCKED the connector processes no new I/O regardless of how "
                            + "many exec threads are free.",
                    "Follow the blocking monitor to its holder in the blocker tree. Poller/Acceptor "
                            + "threads must never contend with application locks - a synchronized "
                            + "custom Executor, logging inside a connection listener, or a JNI-level "
                            + "hang are the usual causes.")
                    .evidence("connector", e.getKey())
                    .evidence("threads", e.getValue())
                    .evidence("dump", atDump)
                    .evidence("confidence", "high")
                    .evidence("whyNotFalsePositive", "healthy pollers/acceptors sit in "
                            + "NioEndpoint$Poller.run / Acceptor.run selector waits (idle patterns); "
                            + "BLOCKED is never their normal state"));
        }
        return out;
    }

    private List<Finding> backgroundProcessor(PatternContext ctx) {
        List<Integer> blockedDumps = new ArrayList<>();
        String name = null;
        for (int i = 0; i < ctx.series().size(); i++) {
            for (ThreadInfo t : ctx.series().get(i).threads()) {
                if (t.name().startsWith("ContainerBackgroundProcessor")
                        && t.state() == ThreadState.BLOCKED) {
                    blockedDumps.add(i);
                    name = t.name();
                }
            }
        }
        if (blockedDumps.isEmpty()) return List.of();
        boolean persistent = blockedDumps.size() >= Math.max(2, ctx.series().size() / 2);
        return List.of(new Finding("tomcat-background-processor-blocked",
                persistent ? CRITICAL : WARNING,
                "Tomcat background processor BLOCKED in " + blockedDumps.size() + " of "
                        + ctx.series().size() + " dump(s)",
                "\"" + name + "\" runs session expiration, webapp reload scanning, and resource-cache "
                        + "eviction once per backgroundProcessorDelay (default 10 s). While it is "
                        + "BLOCKED, sessions never expire (memory grows) and reloadable contexts stop "
                        + "redeploying - failures that surface long after the lock convoy that caused "
                        + "them.",
                "Find the monitor holder in the blocker tree. Frequent offender: application code "
                        + "synchronizing on the session manager or a servlet-context attribute that "
                        + "session expiry also locks.")
                .evidence("thread", name)
                .evidence("dumps", blockedDumps)
                .evidence("confidence", persistent ? "high" : "medium")
                .evidence("whyNotFalsePositive", "the background processor sleeps between runs "
                        + "(TIMED_WAITING); BLOCKED means it is stuck inside somebody's monitor"));
    }
}
