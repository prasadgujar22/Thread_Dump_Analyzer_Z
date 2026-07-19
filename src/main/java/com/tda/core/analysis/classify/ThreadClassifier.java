package com.tda.core.analysis.classify;

import com.tda.core.model.ThreadInfo;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Per-thread classification (Rules 1-2). Housekeeping and idle threads still appear in
 * the thread tables and state charts, but never produce stuck/long-running findings.
 */
public final class ThreadClassifier {

    public enum Kind { APPLICATION, IDLE, HOUSEKEEPING }

    public record Classification(Kind kind, String label) {
        public boolean neverStuck() { return kind != Kind.APPLICATION; }
    }

    private static final Classification APPLICATION = new Classification(Kind.APPLICATION, null);
    private static final Classification HOUSEKEEPING =
            new Classification(Kind.HOUSEKEEPING, "housekeeping");

    /** JVM housekeeping thread names (Rule 2). */
    private static final List<Pattern> HOUSEKEEPING_NAMES = List.of(
            Pattern.compile("Reference Handler"),
            Pattern.compile("Finalizer"),
            Pattern.compile("Signal Dispatcher"),
            Pattern.compile("Attach Listener"),
            Pattern.compile("Common-Cleaner"),
            Pattern.compile("Notification Thread"),
            Pattern.compile("Service Thread"),
            Pattern.compile("Monitor Deflation Thread"),
            Pattern.compile("C[12] CompilerThread\\d*"),
            Pattern.compile("Sweeper thread"),
            Pattern.compile("VM Thread"),
            Pattern.compile("VM Periodic Task Thread"),
            Pattern.compile("Cleaner-\\d+"),
            // GC workers across collectors: Parallel, G1, ZGC, Shenandoah, CMS
            Pattern.compile("GC task thread#\\d+.*"),
            Pattern.compile("GC Thread#?\\d*"),
            Pattern.compile("G1 (Main Marker|Conc#\\d+|Refine#\\d+|Service|Young RemSet Sampling)"),
            Pattern.compile("ZGC.*"),
            Pattern.compile("Shenandoah.*"),
            Pattern.compile("Concurrent Mark-Sweep GC Thread"),
            Pattern.compile("CMS Main Thread"),
            Pattern.compile("Gang worker#\\d+.*"),
            Pattern.compile("VM JFR Buffer Flush Thread"),
            Pattern.compile("JFR .*"));

    private final IdlePatterns idlePatterns;

    public ThreadClassifier(IdlePatterns idlePatterns) {
        this.idlePatterns = idlePatterns != null ? idlePatterns : IdlePatterns.loadDefault();
    }

    public static boolean isHousekeepingName(String threadName) {
        for (Pattern p : HOUSEKEEPING_NAMES) {
            if (p.matcher(threadName).matches()) return true;
        }
        return false;
    }

    public Classification classify(ThreadInfo t) {
        if (isHousekeepingName(t.name())) return HOUSEKEEPING;
        String idle = idlePatterns.labelFor(t);
        if (idle != null) return new Classification(Kind.IDLE, idle);
        return APPLICATION;
    }

    /** True when a stack frame belongs to application code (not JDK / not a container). */
    public static boolean isApplicationFrame(String classFqn) {
        return !(classFqn.startsWith("java.") || classFqn.startsWith("javax.")
                || classFqn.startsWith("jakarta.") || classFqn.startsWith("jdk.")
                || classFqn.startsWith("sun.") || classFqn.startsWith("com.sun.")
                || classFqn.startsWith("org.apache.catalina.") || classFqn.startsWith("org.apache.tomcat.")
                || classFqn.startsWith("org.apache.coyote.") || classFqn.startsWith("weblogic.")
                || classFqn.startsWith("com.ibm.ws.") || classFqn.startsWith("com.ibm.io.")
                || classFqn.startsWith("io.undertow.") || classFqn.startsWith("org.jboss.")
                || classFqn.startsWith("org.wildfly.") || classFqn.startsWith("org.xnio."));
    }
}
