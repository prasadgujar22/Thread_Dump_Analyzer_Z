package com.tda.core.analysis.middleware;

import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Builds the "middleware" JSON node of the analysis result: the detected server profile
 * plus a per-dump health table of that server's worker groups (WebLogic queues, Tomcat
 * connectors, WebSphere/Liberty pools). Uses the same {@link PoolHealth} math as the
 * finding analyzers so panels and findings always agree.
 */
public final class MiddlewarePanel {

    private MiddlewarePanel() {}

    public static Map<String, Object> build(DumpSeries series, MiddlewareDetector.Profile profile,
                                            ThreadClassifier classifier) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("platform", profile.platform().name());
        m.put("display", profile.display());
        m.put("score", profile.score());
        m.put("evidence", profile.evidence());

        Function<String, String> grouper = switch (profile.platform()) {
            case WEBLOGIC -> n -> {
                String q = WebLogicAnalyzer.queueOf(n);
                return q != null ? "queue '" + q + "'" : null;
            };
            case TOMCAT -> TomcatAnalyzer::connectorOf;
            case WEBSPHERE -> MiddlewarePanel::webSpherePoolOf;
            case LIBERTY -> n ->
                    WebSphereAnalyzer.LIBERTY_EXEC.matcher(n).matches() ? "Default Executor" : null;
            default -> n -> null;
        };

        // group -> per-dump snapshots (null-padded so columns line up)
        Map<String, PoolHealth.Snapshot[]> groups = new LinkedHashMap<>();
        for (int i = 0; i < series.size(); i++) {
            ThreadDump d = series.get(i);
            List<String> present = new ArrayList<>();
            for (ThreadInfo t : d.threads()) {
                String g = grouper.apply(t.name());
                if (g != null && !present.contains(g)) present.add(g);
            }
            for (String g : present) {
                PoolHealth.Snapshot[] arr = groups.computeIfAbsent(g,
                        k -> new PoolHealth.Snapshot[series.size()]);
                arr[i] = PoolHealth.snapshot(d, i, n -> g.equals(grouper.apply(n)), classifier);
            }
        }

        List<Object> rows = new ArrayList<>();
        for (Map.Entry<String, PoolHealth.Snapshot[]> e : groups.entrySet()) {
            List<Object> perDump = new ArrayList<>();
            for (PoolHealth.Snapshot s : e.getValue()) {
                if (s == null) { perDump.add(null); continue; }
                Map<String, Object> cell = new LinkedHashMap<>();
                cell.put("total", s.total());
                cell.put("busy", s.busy());
                cell.put("blocked", s.blocked());
                if (s.stuckMarked() > 0) cell.put("stuck", s.stuckMarked());
                if (s.standby() > 0) cell.put("standby", s.standby());
                cell.put("saturated", s.saturated());
                perDump.add(cell);
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("group", e.getKey());
            row.put("perDump", perDump);
            rows.add(row);
        }
        m.put("groups", rows);
        return m;
    }

    /** Traditional-WAS pool of a thread name, or null. */
    static String webSpherePoolOf(String name) {
        if (WebSphereAnalyzer.WEBCONTAINER.matcher(name).matches()) return "WebContainer";
        if (name.startsWith("ORB.thread.pool")) return "ORB.thread.pool";
        if (name.startsWith("SIBJMSRAThreadPool")) return "SIBJMSRAThreadPool";
        if (name.startsWith("WMQJCAResourceAdapter")) return "WMQJCAResourceAdapter";
        if (name.startsWith("SoapConnectorThreadPool")) return "SoapConnectorThreadPool";
        if (name.startsWith("server.startup :")) return "server.startup";
        if (name.startsWith("Deferrable Alarm :") || name.startsWith("Non-deferrable Alarm :")) {
            return "Alarm threads";
        }
        if (name.startsWith("TCPChannel.DCS") || name.startsWith("HAManager.")) return "HAManager/DCS";
        return null;
    }
}
