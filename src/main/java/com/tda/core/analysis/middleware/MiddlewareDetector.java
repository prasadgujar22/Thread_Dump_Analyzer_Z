package com.tda.core.analysis.middleware;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Classifies which application server produced a dump series, from thread-name shapes,
 * frame packages, and the JVM banner. The winning platform gates the platform-specific
 * health analyzers so WebLogic heuristics never fire on a Tomcat dump (and vice versa).
 *
 * <p>Deterministic and explainable: each matched signal contributes a weighted score and
 * a human-readable evidence line; the profile carries both.
 */
public final class MiddlewareDetector {

    public enum Platform {
        WEBLOGIC("Oracle WebLogic Server"),
        WEBSPHERE("IBM WebSphere Application Server (traditional)"),
        LIBERTY("IBM WebSphere Liberty / Open Liberty"),
        TOMCAT("Apache Tomcat"),
        WILDFLY("JBoss EAP / WildFly"),
        UNKNOWN("Unknown / plain JVM");

        private final String display;
        Platform(String display) { this.display = display; }
        public String display() { return display; }
    }

    public record Profile(Platform platform, String display, int score, List<String> evidence) {}

    private record Signal(Platform platform, int weight, String evidence, Pattern threadName,
                          String framePrefix, String bannerNeedle) {
        static Signal name(Platform p, int w, String ev, String regex) {
            return new Signal(p, w, ev, Pattern.compile(regex), null, null);
        }
        static Signal frame(Platform p, int w, String ev, String prefix) {
            return new Signal(p, w, ev, null, prefix, null);
        }
        static Signal banner(Platform p, int w, String ev, String needle) {
            return new Signal(p, w, ev, null, null, needle);
        }
    }

    private static final List<Signal> SIGNALS = List.of(
            // WebLogic
            Signal.name(Platform.WEBLOGIC, 5, "ExecuteThread work-manager thread names",
                    "^(?:\\[(?:STUCK|ACTIVE|STANDBY|HOGGING)] )?ExecuteThread:? '?\\d+'? for queue: .*"),
            Signal.name(Platform.WEBLOGIC, 3, "weblogic.timers / DynamicListenThread threads",
                    "^(weblogic\\.timers\\..*|DynamicListenThread.*|weblogic\\.GCMonitor)$"),
            Signal.frame(Platform.WEBLOGIC, 4, "weblogic.* frames on thread stacks", "weblogic."),
            // WebSphere traditional
            Signal.name(Platform.WEBSPHERE, 5, "'WebContainer : N' thread pool names",
                    "^WebContainer : \\d+$"),
            Signal.name(Platform.WEBSPHERE, 3, "WAS system pools (ORB / SIB / alarms / HAManager)",
                    "^(ORB\\.thread\\.pool.*|SIBJMSRAThreadPool.*|WMQJCAResourceAdapter.*|"
                    + "Deferrable Alarm : \\d+|Non-deferrable Alarm : \\d+|server\\.startup : \\d+|"
                    + "HAManager\\..*|SoapConnectorThreadPool : \\d+|TCPChannel\\.DCS : \\d+)$"),
            Signal.frame(Platform.WEBSPHERE, 4, "com.ibm.ws.* frames on thread stacks", "com.ibm.ws."),
            Signal.banner(Platform.WEBSPHERE, 2, "IBM J9 VM banner", "J9 VM"),
            // Liberty (checked before generic WebSphere frames would decide; scored independently)
            Signal.name(Platform.LIBERTY, 5, "'Default Executor-thread-N' pool names",
                    "^Default Executor-thread-\\d+$"),
            Signal.frame(Platform.LIBERTY, 4, "com.ibm.ws.threading.* Liberty executor frames",
                    "com.ibm.ws.threading."),
            // Tomcat (also matches embedded Tomcat in Spring Boot)
            Signal.name(Platform.TOMCAT, 5, "http/ajp connector exec thread names",
                    "^(?:http|https|ajp)-[\\w.-]+-exec-\\d+$"),
            Signal.name(Platform.TOMCAT, 4, "Catalina utility / background-processor threads",
                    "^(catalina-exec-\\d+|Catalina-utility-\\d+|ContainerBackgroundProcessor.*|"
                    + "(?:http|https|ajp)-[\\w.-]+-(?:Poller|Acceptor|ClientPoller|BlockPoller).*)$"),
            Signal.frame(Platform.TOMCAT, 4, "org.apache.catalina/tomcat/coyote frames", "org.apache.catalina."),
            Signal.frame(Platform.TOMCAT, 3, "org.apache.tomcat.* frames", "org.apache.tomcat."),
            Signal.frame(Platform.TOMCAT, 3, "org.apache.coyote.* frames", "org.apache.coyote."),
            // WildFly / JBoss EAP
            Signal.name(Platform.WILDFLY, 5, "'default task-N' / XNIO worker names",
                    "^(default task-\\d+|XNIO-\\d+ (task|I/O)-\\d+.*|EJB default - \\d+)$"),
            Signal.frame(Platform.WILDFLY, 4, "org.jboss/org.wildfly/io.undertow frames", "org.jboss."),
            Signal.frame(Platform.WILDFLY, 3, "io.undertow.* frames", "io.undertow."));

    public static Profile detect(DumpSeries series) {
        Map<Platform, Integer> scores = new EnumMap<>(Platform.class);
        Map<Platform, Set<String>> evidence = new EnumMap<>(Platform.class);

        for (Signal s : SIGNALS) {
            int hits = 0;
            for (ThreadDump d : series.dumps()) {
                if (s.bannerNeedle() != null) {
                    if (d.jvmBanner().contains(s.bannerNeedle())) hits++;
                    continue;
                }
                for (ThreadInfo t : d.threads()) {
                    if (s.threadName() != null) {
                        if (s.threadName().matcher(t.name()).matches()) hits++;
                    } else {
                        for (StackFrame f : t.frames()) {
                            if (f.classFqn().startsWith(s.framePrefix())) { hits++; break; }
                        }
                    }
                }
            }
            if (hits > 0) {
                scores.merge(s.platform(), s.weight(), Integer::sum);
                evidence.computeIfAbsent(s.platform(), k -> new LinkedHashSet<>())
                        .add(s.evidence() + " (" + hits + " hit" + (hits == 1 ? "" : "s") + ")");
            }
        }

        // Liberty is a superset of some WebSphere signals (com.ibm.ws.*): when Liberty's own
        // executor names are present, Liberty wins the tie; otherwise traditional WAS does.
        Platform best = Platform.UNKNOWN;
        int bestScore = 0;
        for (Map.Entry<Platform, Integer> e : scores.entrySet()) {
            if (e.getValue() > bestScore
                    || (e.getValue() == bestScore && e.getKey() == Platform.LIBERTY)) {
                best = e.getKey();
                bestScore = e.getValue();
            }
        }
        if (bestScore < 4) best = Platform.UNKNOWN; // one weak signal is not a verdict

        List<String> ev = new ArrayList<>(evidence.getOrDefault(best, Set.of()));
        return new Profile(best, best.display(), bestScore, ev);
    }
}
