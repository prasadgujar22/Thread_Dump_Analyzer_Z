package com.tda.core.analysis.single;

import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Groups threads into pools by name pattern. Built-in rules cover the common middleware
 * stacks (WebLogic, WebSphere, Tomcat, JBoss/WildFly, JDK executors); user-defined
 * {@code name=regex} rules run first and win.
 */
public final class PoolGrouper {

    public record PoolStats(String pool, int count, Map<ThreadState, Integer> states,
                            List<String> threadNames, int stuckCount) {}

    private record Rule(Pattern pattern, Function<Matcher, String> poolName) {}

    private final List<Rule> rules = new ArrayList<>();

    public PoolGrouper() { this(Map.of()); }

    /** @param userPatterns pool-name → regex; a regex with a capture group appends group(1) to the name. */
    public PoolGrouper(Map<String, String> userPatterns) {
        for (Map.Entry<String, String> e : userPatterns.entrySet()) {
            Pattern p = Pattern.compile(e.getValue());
            String base = e.getKey();
            rules.add(new Rule(p, m -> m.groupCount() >= 1 && m.group(1) != null
                    ? base + " " + m.group(1) : base));
        }
        // WebLogic: [STUCK] ExecuteThread: '12' for queue: 'weblogic.kernel.Default (self-tuning)'
        rules.add(new Rule(
                Pattern.compile("^(?:\\[(?:STUCK|ACTIVE|STANDBY|HOGGING)] )?ExecuteThread:? '?\\d+'? for queue: '(.+)'.*"),
                m -> "WebLogic queue '" + m.group(1) + "'"));
        // WebSphere traditional: WebContainer : 12 plus the system pools
        rules.add(new Rule(Pattern.compile("^WebContainer : \\d+$"), m -> "WebSphere WebContainer"));
        rules.add(new Rule(Pattern.compile("^(SIBJMSRAThreadPool|WMQJCAResourceAdapter|ORB\\.thread\\.pool|SoapConnectorThreadPool|TCPChannel\\.DCS)\\b.*"),
                m -> "WebSphere " + m.group(1)));
        rules.add(new Rule(Pattern.compile("^(server\\.startup|Deferrable Alarm|Non-deferrable Alarm) : \\d+$"),
                m -> "WebSphere " + m.group(1)));
        // WebSphere Liberty / Open Liberty self-tuning executor
        rules.add(new Rule(Pattern.compile("^Default Executor-thread-\\d+$"), m -> "Liberty default executor"));
        // Tomcat / Spring Boot: http-nio-8080-exec-3, https-jsse-nio-8443-exec-1, ajp-nio-...-exec-N
        rules.add(new Rule(Pattern.compile("^((?:http|https|ajp)-[\\w.-]+)-exec-\\d+$"), m -> m.group(1)));
        rules.add(new Rule(Pattern.compile("^(catalina-exec)-\\d+$"), m -> m.group(1)));
        rules.add(new Rule(Pattern.compile("^(Catalina-utility)-\\d+$"), m -> m.group(1)));
        // JBoss / WildFly / Undertow
        rules.add(new Rule(Pattern.compile("^default task-\\d+$"), m -> "WildFly 'default' workers"));
        rules.add(new Rule(Pattern.compile("^(EJB default) - \\d+$"), m -> "WildFly EJB default"));
        rules.add(new Rule(Pattern.compile("^(XNIO-\\d+) task-\\d+$"), m -> m.group(1) + " tasks"));
        rules.add(new Rule(Pattern.compile("^(XNIO-\\d+) I/O-\\d+$"), m -> m.group(1) + " I/O"));
        // ForkJoin: ForkJoinPool.commonPool-worker-3 / ForkJoinPool-2-worker-11
        rules.add(new Rule(Pattern.compile("^(ForkJoinPool(?:\\.commonPool|-\\d+))-worker-\\d+$"), m -> m.group(1)));
        // JDK Executors.newFixedThreadPool: pool-7-thread-12
        rules.add(new Rule(Pattern.compile("^(pool-\\d+)-thread-\\d+$"), m -> m.group(1)));
        // Common client pools worth trending
        rules.add(new Rule(Pattern.compile("^(HikariPool-\\d+)[: ].*"), m -> m.group(1)));
        rules.add(new Rule(Pattern.compile("^(grpc-default-executor)-\\d+$"), m -> m.group(1)));
        rules.add(new Rule(Pattern.compile("^(scheduling|task-scheduler|taskExecutor)-\\d+$"), m -> m.group(1)));
    }

    /** Pool name for a thread, or null when the thread matches no rule. */
    public String poolOf(String threadName) {
        for (Rule r : rules) {
            Matcher m = r.pattern().matcher(threadName);
            if (m.matches()) return r.poolName().apply(m);
        }
        return null;
    }

    public List<PoolStats> analyze(ThreadDump dump) {
        Map<String, List<ThreadInfo>> byPool = new LinkedHashMap<>();
        for (ThreadInfo t : dump.javaThreads()) {
            String pool = poolOf(t.name());
            if (pool != null) byPool.computeIfAbsent(pool, k -> new ArrayList<>()).add(t);
        }
        List<PoolStats> out = new ArrayList<>();
        for (Map.Entry<String, List<ThreadInfo>> e : byPool.entrySet()) {
            Map<ThreadState, Integer> states = new EnumMap<>(ThreadState.class);
            List<String> names = new ArrayList<>();
            int stuck = 0;
            for (ThreadInfo t : e.getValue()) {
                states.merge(t.state(), 1, Integer::sum);
                names.add(t.name());
                if (isStuckMarked(t.name())) stuck++;
            }
            out.add(new PoolStats(e.getKey(), e.getValue().size(), states, names, stuck));
        }
        out.sort((a, b) -> Integer.compare(b.count(), a.count()));
        return out;
    }

    /** WebLogic marks threads it considers stuck/hogging in the thread name itself. */
    public static boolean isStuckMarked(String threadName) {
        return threadName.contains("[STUCK]") || threadName.contains("[HOGGING]");
    }
}
