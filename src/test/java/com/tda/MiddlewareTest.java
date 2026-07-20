package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.middleware.MiddlewareDetector;
import com.tda.core.model.DumpSeries;
import com.tda.core.parse.DumpSetLoader;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Middleware detection + the WebLogic/Tomcat/WebSphere platform analyzers. */
class MiddlewareTest {

    // ---------- detection ----------

    @Test
    void detectsWebLogicFromExecuteThreads() {
        var p = MiddlewareDetector.detect(Fixtures.series("stuck_series_weblogic.log"));
        assertEquals(MiddlewareDetector.Platform.WEBLOGIC, p.platform());
        assertFalse(p.evidence().isEmpty());
    }

    @Test
    void detectsTomcatFromConnectorThreads() {
        var p = MiddlewareDetector.detect(Fixtures.series("idle_tomcat_jdk8.log"));
        assertEquals(MiddlewareDetector.Platform.TOMCAT, p.platform());
    }

    @Test
    void detectsWebSphereFromJavacore() {
        var p = MiddlewareDetector.detect(Fixtures.series("javacore_was_jdk8.txt"));
        assertEquals(MiddlewareDetector.Platform.WEBSPHERE, p.platform());
    }

    @Test
    void healthyTomcatFixtureDetectsAsTomcat() {
        // the "healthy" fixture is an embedded-Tomcat app (http-nio-8080-exec threads)
        var p = MiddlewareDetector.detect(Fixtures.series("healthy_jdk8.txt"));
        assertEquals(MiddlewareDetector.Platform.TOMCAT, p.platform());
    }

    @Test
    void plainJvmStaysUnknown() {
        var p = MiddlewareDetector.detect(analyzeSeries(saturatedDump("worker-%d", 3, "")));
        assertEquals(MiddlewareDetector.Platform.UNKNOWN, p.platform());
    }

    private static DumpSeries analyzeSeries(String text) {
        try {
            return new DumpSetLoader().loadFromStrings(List.of("t"), List.of(text));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---------- analyzers, end-to-end through the engine ----------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> analyze(String text) {
        try {
            DumpSeries s = new DumpSetLoader().loadFromStrings(List.of("t"), List.of(text));
            return new AnalysisEngine(new AnalysisOptions()).analyze(s, List.of());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> findings(Map<String, Object> result) {
        return (List<Map<String, Object>>) (List<?>) result.get("findings");
    }

    private static Map<String, Object> byId(List<Map<String, Object>> fs, String id) {
        return fs.stream().filter(f -> id.equals(f.get("id"))).findFirst()
                .orElseThrow(() -> new AssertionError("missing finding " + id + " in "
                        + fs.stream().map(f -> f.get("id")).toList()));
    }

    private static boolean has(List<Map<String, Object>> fs, String id) {
        return fs.stream().anyMatch(f -> id.equals(f.get("id")));
    }

    /** A dump where every worker of the pool is busy in an application frame. */
    private static String saturatedDump(String namePattern, int n, String extraThreads) {
        StringBuilder sb = new StringBuilder("""
                2026-07-16 19:00:00
                Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                """);
        for (int i = 1; i <= n; i++) {
            sb.append(String.format("""
                    "%s" #%d daemon prio=5 os_prio=0 tid=0x0000000000a%02d000 nid=0x9%02d runnable  [0x0000000000b%02d000]
                       java.lang.Thread.State: RUNNABLE
                    \tat java.net.SocketInputStream.socketRead0(Native Method)
                    \tat com.acme.svc.SlowBackendClient.call(SlowBackendClient.java:42)
                    \tat com.acme.web.OrderServlet.doPost(OrderServlet.java:31)

                    """, String.format(namePattern, i), 40 + i, i, i, i));
        }
        sb.append(extraThreads);
        return sb.toString();
    }

    @Test
    void tomcatConnectorExhaustionFires() {
        String dump = saturatedDump("http-nio-8080-exec-%d", 9, """
                "http-nio-8080-Poller" #90 daemon prio=5 os_prio=0 tid=0x0000000000c01000 nid=0xa01 runnable  [0x0000000000d01000]
                   java.lang.Thread.State: RUNNABLE
                \tat sun.nio.ch.EPoll.wait(Native Method)
                \tat org.apache.tomcat.util.net.NioEndpoint$Poller.run(NioEndpoint.java:596)

                "http-nio-8080-Acceptor" #91 daemon prio=5 os_prio=0 tid=0x0000000000c02000 nid=0xa02 runnable  [0x0000000000d02000]
                   java.lang.Thread.State: RUNNABLE
                \tat sun.nio.ch.Net.accept(Native Method)
                \tat org.apache.tomcat.util.net.Acceptor.run(Acceptor.java:129)

                """);
        var result = analyze(dump);
        var f = byId(findings(result), "tomcat-connector-exhaustion");
        assertEquals("WARNING", f.get("severity"), "single dump, nothing blocked -> WARNING");
        Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
        assertEquals("http-nio-8080", ev.get("connector"));
        assertEquals(9, ev.get("threads"));

        Map<String, Object> mw = (Map<String, Object>) result.get("middleware");
        assertEquals("TOMCAT", mw.get("platform"));
        assertFalse(((List<?>) mw.get("groups")).isEmpty(), "connector panel rows present");
    }

    @Test
    void idleTomcatPoolIsNotExhausted() {
        var fs = findings(new AnalysisEngine(new AnalysisOptions())
                .analyze(Fixtures.series("idle_tomcat_jdk8.log"), List.of()));
        assertFalse(has(fs, "tomcat-connector-exhaustion"),
                "workers parked in TaskQueue.take are idle, not busy");
        assertFalse(has(fs, "tomcat-poller-blocked"));
    }

    @Test
    void tomcatPollerBlockedIsCritical() {
        String dump = """
                2026-07-16 19:00:00
                Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                "http-nio-8080-exec-1" #41 daemon prio=5 os_prio=0 tid=0x0000000000a01000 nid=0x901 waiting on condition  [0x0000000000b01000]
                   java.lang.Thread.State: WAITING (parking)
                \tat jdk.internal.misc.Unsafe.park(Native Method)
                \tat org.apache.tomcat.util.threads.TaskQueue.take(TaskQueue.java:146)

                "http-nio-8080-Poller" #90 daemon prio=5 os_prio=0 tid=0x0000000000c01000 nid=0xa01 waiting for monitor entry  [0x0000000000d01000]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat com.acme.metrics.ConnectionCounter.onSocket(ConnectionCounter.java:19)
                \t- waiting to lock <0x00000000e0000010> (a com.acme.metrics.ConnectionCounter)
                \tat org.apache.tomcat.util.net.NioEndpoint$Poller.run(NioEndpoint.java:602)

                """;
        var f = byId(findings(analyze(dump)), "tomcat-poller-blocked");
        assertEquals("CRITICAL", f.get("severity"));
    }

    @Test
    void weblogicStarvationFiresOnlyWithoutStandbyReserve() {
        // 8 busy ACTIVE threads, no STANDBY, no idle -> starvation
        String saturated = saturatedDump(
                "[ACTIVE] ExecuteThread: '%d' for queue: 'weblogic.kernel.Default (self-tuning)'", 8, "");
        var f = byId(findings(analyze(saturated)), "weblogic-thread-starvation");
        Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
        assertEquals("weblogic.kernel.Default (self-tuning)", ev.get("queue"));

        // same pool with a STANDBY thread in reserve -> healthy, no finding
        String withReserve = saturatedDump(
                "[ACTIVE] ExecuteThread: '%d' for queue: 'weblogic.kernel.Default (self-tuning)'", 8, """
                "[STANDBY] ExecuteThread: '20' for queue: 'weblogic.kernel.Default (self-tuning)'" #60 daemon prio=5 os_prio=0 tid=0x0000000000c03000 nid=0xa03 in Object.wait()  [0x0000000000d03000]
                   java.lang.Thread.State: WAITING (on object monitor)
                \tat java.lang.Object.wait(Native Method)
                \tat weblogic.work.ExecuteThread.waitForRequest(ExecuteThread.java:198)

                """);
        assertFalse(has(findings(analyze(withReserve)), "weblogic-thread-starvation"));
    }

    @Test
    void weblogicSeriesFixtureDoesNotStarve() {
        var fs = findings(new AnalysisEngine(new AnalysisOptions())
                .analyze(Fixtures.series("stuck_series_weblogic.log"), List.of()));
        assertFalse(has(fs, "weblogic-thread-starvation"),
                "the fixture keeps STANDBY threads in reserve");
    }

    @Test
    void weblogicMuxerBlockedDetected() {
        String dump = saturatedDump(
                "[ACTIVE] ExecuteThread: '%d' for queue: 'weblogic.kernel.Default (self-tuning)'", 2, """
                "ExecuteThread: '0' for queue: 'weblogic.socket.Muxer'" #70 daemon prio=5 os_prio=0 tid=0x0000000000c04000 nid=0xa04 waiting for monitor entry  [0x0000000000d04000]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat org.apache.log4j.Category.callAppenders(Category.java:204)
                \t- waiting to lock <0x00000000e0000020> (a org.apache.log4j.spi.RootLogger)
                \tat weblogic.socket.SocketMuxer.processSockets(SocketMuxer.java:100)

                "ExecuteThread: '1' for queue: 'weblogic.socket.Muxer'" #71 daemon prio=5 os_prio=0 tid=0x0000000000c05000 nid=0xa05 waiting for monitor entry  [0x0000000000d05000]
                   java.lang.Thread.State: BLOCKED (on object monitor)
                \tat org.apache.log4j.Category.callAppenders(Category.java:204)
                \t- waiting to lock <0x00000000e0000020> (a org.apache.log4j.spi.RootLogger)
                \tat weblogic.socket.SocketMuxer.processSockets(SocketMuxer.java:100)

                """);
        var f = byId(findings(analyze(dump)), "weblogic-muxer-blocked");
        assertEquals("CRITICAL", f.get("severity"), "every muxer blocked = front end down");
    }

    @Test
    void webSphereSaturationFromJavacoreShapedNames() {
        String dump = saturatedDump("WebContainer : %d", 9, "");
        var f = byId(findings(analyze(dump)), "websphere-webcontainer-saturation");
        Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
        assertEquals(9, ev.get("threads"));
    }

    @Test
    void wasJavacoreFixtureIsNotSaturated() {
        // 4 WebContainer threads, one idle in BoundedBuffer -> below floor and not saturated
        var fs = findings(new AnalysisEngine(new AnalysisOptions())
                .analyze(Fixtures.series("javacore_was_jdk8.txt"), List.of()));
        assertFalse(has(fs, "websphere-webcontainer-saturation"));
        // but the blocked chain behind WebContainer : 1 surfaces via the generic top-blocker
        assertTrue(has(fs, "top-blocker"));
    }

    @Test
    void oomJavacoreGetsCriticalNote() {
        String javacore = Fixtures.read("javacore_was_jdk8.txt").replace(
                "1TISIGINFO     Dump Event \"user\" (00004000) received ",
                "1TISIGINFO     Dump Event \"systhrow\" (00040000) Detail \"java/lang/OutOfMemoryError\" \"Java heap space\" received ");
        var f = byId(findings(analyze(javacore)), "javacore-oom-trigger");
        assertEquals("CRITICAL", f.get("severity"));
    }

    @Test
    void platformAnalyzersAreGated() {
        // WebContainer-style saturation on a dump that is detected as Tomcat must not fire
        String dump = saturatedDump("http-nio-8080-exec-%d", 9, "");
        var fs = findings(analyze(dump));
        assertFalse(has(fs, "websphere-webcontainer-saturation"));
        assertFalse(has(fs, "weblogic-thread-starvation"));
    }

    @Test
    void libertyExecutorSaturationNeedsBlockedMembers() {
        String allBusyNoneBlocked = saturatedDump("Default Executor-thread-%d", 9, "");
        assertFalse(has(findings(analyze(allBusyNoneBlocked)), "liberty-executor-saturation"),
                "Liberty grows its executor - busy alone is not an incident");

        StringBuilder blocked = new StringBuilder(saturatedDump("Default Executor-thread-%d", 6, ""));
        for (int i = 7; i <= 12; i++) {
            blocked.append(String.format("""
                    "Default Executor-thread-%d" #%d daemon prio=5 os_prio=0 tid=0x0000000000e%02d000 nid=0xb%02d waiting for monitor entry  [0x0000000000f%02d000]
                       java.lang.Thread.State: BLOCKED (on object monitor)
                    \tat com.acme.cache.LegacyCache.get(LegacyCache.java:77)
                    \t- waiting to lock <0x00000000e0000030> (a com.acme.cache.LegacyCache)
                    \tat com.ibm.ws.threading.internal.Worker.run(Worker.java:64)

                    """, i, 40 + i, i, i, i));
        }
        var f = byId(findings(analyze(blocked.toString())), "liberty-executor-saturation");
        Map<String, Object> ev = (Map<String, Object>) f.get("evidence");
        assertEquals(6, ev.get("blocked"));
    }
}
