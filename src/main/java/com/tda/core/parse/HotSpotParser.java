package com.tda.core.parse;

import com.tda.core.model.LockRef;
import com.tda.core.model.ParseIssue;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Line-oriented state machine that parses one HotSpot thread-dump section
 * (jstack / jcmd Thread.print / kill -3), covering JDK 8 through 21 formats:
 * <ul>
 *   <li>JDK 8: {@code "name" #1 daemon prio=5 os_prio=0 tid=0x... nid=0x2f03 runnable [0x...]}</li>
 *   <li>JDK 11+: adds {@code cpu=1.2ms elapsed=3.4s} header fields</li>
 *   <li>JDK 19+: adds {@code [ostid]} and decimal {@code nid}</li>
 *   <li>VM/GC/JIT threads without {@code #id} or a Java stack</li>
 *   <li>{@code jstack -l} "Locked ownable synchronizers:" sections</li>
 *   <li>the JVM's own "Found one Java-level deadlock" report</li>
 * </ul>
 * Unrecognized lines never abort parsing; they are counted and surfaced as {@link ParseIssue}s.
 */
public final class HotSpotParser {

    // A real thread header always carries tid=; the deadlock report's `"name":` lines do not.
    private static final Pattern HEADER = Pattern.compile("^\"(?<name>.*)\"\\s+(?<attrs>.*tid=0x[0-9a-fA-F]+.*)$");
    private static final Pattern JAVA_ID = Pattern.compile("#(\\d+)");
    private static final Pattern OS_TID = Pattern.compile("\\[(\\d+)]");
    private static final Pattern PRIO = Pattern.compile("(?<![a-z_])prio=(\\d+)");
    private static final Pattern OS_PRIO = Pattern.compile("os_prio=(-?\\d+)");
    private static final Pattern CPU = Pattern.compile("cpu=([\\d.]+)ms");
    private static final Pattern ELAPSED = Pattern.compile("elapsed=([\\d.]+)s");
    private static final Pattern TID = Pattern.compile("tid=(0x[0-9a-fA-F]+)");
    private static final Pattern NID = Pattern.compile("nid=(0x[0-9a-fA-F]+|\\d+)");
    private static final Pattern CONDITION = Pattern.compile(
            "nid=(?:0x[0-9a-fA-F]+|\\d+)\\s+(?<cond>.*?)\\s*(\\[0x[0-9a-fA-F]+])?\\s*$");
    private static final Pattern STATE_LINE = Pattern.compile("^\\s*java\\.lang\\.Thread\\.State:\\s+(?<state>.+)$");
    private static final Pattern LOCK_LINE = Pattern.compile(
            "^\\s*-\\s+(?<verb>locked|waiting to lock|waiting on|parking to wait for|waiting to re-lock in wait\\(\\))"
            + "\\s+<(?<addr>0x[0-9a-fA-F]+|no object reference available)>(\\s+\\(a\\s+(?<cls>[^)]+)\\))?\\s*$");
    private static final Pattern ELIMINATED_LINE = Pattern.compile(
            "^\\s*-\\s+eliminated\\s+<(?<what>[^>]*)>(\\s+\\(a\\s+(?<cls>[^)]+)\\))?\\s*$");
    private static final Pattern SYNC_ENTRY = Pattern.compile(
            "^\\s*-\\s+<(?<addr>0x[0-9a-fA-F]+)>\\s+\\(a\\s+(?<cls>[^)]+)\\)\\s*$");
    private static final Pattern DEADLOCK_NAME = Pattern.compile("^\"(?<name>.+)\":\\s*$");

    private ThreadDump dump;
    private ThreadInfo current;      // thread block currently being read
    private ThreadInfo lastThread;   // most recently finished thread (owns a following synchronizers section)
    private boolean inSynchronizers;
    private boolean inDeadlockNames;
    private boolean inDeadlockStacks; // "Java stack information for the threads listed above"
    private boolean tail;             // past "JNI global refs" - ignore the rest quietly
    private List<String> cycle;
    private int unrecognized;
    private String firstUnrecognized;

    public void begin(String sourceName, Instant timestamp) {
        dump = new ThreadDump();
        dump.setSourceName(sourceName);
        dump.setTimestamp(timestamp);
        current = null;
        lastThread = null;
        inSynchronizers = false;
        inDeadlockNames = false;
        inDeadlockStacks = false;
        tail = false;
        cycle = null;
        unrecognized = 0;
        firstUnrecognized = null;
    }

    public boolean isOpen() { return dump != null; }

    public ThreadDump end() {
        finishCurrent();
        closeCycle();
        if (unrecognized > 0) {
            dump.issues().add(new ParseIssue(dump.sourceName(),
                    unrecognized + " unrecognized line(s) skipped inside the dump (first: \""
                    + firstUnrecognized + "\")"));
        }
        ThreadDump d = dump;
        dump = null;
        return d;
    }

    public void accept(String line) {
        if (dump == null) throw new IllegalStateException("begin() not called");
        String trimmed = line.trim();

        if (trimmed.startsWith("Full thread dump") || trimmed.startsWith("Full Java thread dump")) {
            dump.setJvmBanner(trimmed);
            return;
        }

        // ---- deadlock report ----
        if (trimmed.startsWith("Found one Java-level deadlock")) {
            finishCurrent();
            closeCycle();
            inDeadlockNames = true;
            inDeadlockStacks = false;
            cycle = new ArrayList<>();
            return;
        }
        if (inDeadlockNames || inDeadlockStacks) {
            if (trimmed.startsWith("Java stack information")) {
                inDeadlockNames = false;
                inDeadlockStacks = true;
                return;
            }
            if (trimmed.matches("Found \\d+ deadlock(s)?\\.?")) {
                closeCycle();
                inDeadlockStacks = false;
                return;
            }
            if (inDeadlockNames) {
                Matcher dn = DEADLOCK_NAME.matcher(trimmed);
                if (dn.matches()) { cycle.add(dn.group("name")); return; }
                if (trimmed.isEmpty()) { closeCycle(); inDeadlockNames = false; return; }
                return; // "waiting to lock monitor ..." / "which is held by ..." detail lines
            }
            return; // repeated stacks inside the deadlock report - already parsed above
        }

        // ---- thread header ----
        Matcher h = trimmed.startsWith("\"") ? HEADER.matcher(trimmed) : null;
        if (h != null && h.matches()) {
            finishCurrent();
            tail = false;
            current = parseHeader(h.group("name"), h.group("attrs"));
            current.appendRaw(line);
            return;
        }

        if (current == null && lastThread == null && trimmed.isEmpty()) return;

        // ---- state line ----
        Matcher st = STATE_LINE.matcher(line);
        if (st.matches() && current != null) {
            current.setStateDetail(st.group("state").trim());
            current.setState(ThreadState.parse(st.group("state")));
            current.appendRaw(line);
            return;
        }

        // ---- synchronizers section (follows the blank line after a thread's stack) ----
        if (trimmed.startsWith("Locked ownable synchronizers")) {
            inSynchronizers = true;
            dump.markSynchronizerSection();
            return;
        }
        if (inSynchronizers) {
            ThreadInfo owner = current != null ? current : lastThread;
            Matcher se = SYNC_ENTRY.matcher(line);
            if (se.matches()) {
                if (owner != null) {
                    owner.locks().add(new LockRef(LockRef.Kind.LOCKED_SYNCHRONIZER,
                            se.group("addr"), se.group("cls"), -1));
                    owner.appendRaw(line);
                }
                return;
            }
            inSynchronizers = false;
            if (trimmed.equals("- None") || trimmed.isEmpty()) return;
            // fall through: some other line ended the section
        }

        if (current != null) {
            // ---- stack frame ----
            StackFrame f = StackFrame.parse(line);
            if (f != null) {
                current.frames().add(f);
                current.appendRaw(line);
                return;
            }
            // ---- lock annotations ----
            Matcher lk = LOCK_LINE.matcher(line);
            if (lk.matches()) {
                String verb = lk.group("verb");
                String addr = lk.group("addr");
                if (addr.startsWith("0x")) {
                    LockRef.Kind kind = switch (verb) {
                        case "locked" -> LockRef.Kind.LOCKED_MONITOR;
                        case "waiting to lock" -> LockRef.Kind.WAITING_TO_LOCK;
                        case "parking to wait for" -> LockRef.Kind.PARKING_TO_WAIT_FOR;
                        default -> LockRef.Kind.WAITING_ON; // waiting on / waiting to re-lock
                    };
                    current.locks().add(new LockRef(kind, addr, lk.group("cls"),
                            current.frames().size() - 1));
                }
                current.appendRaw(line);
                return;
            }
            Matcher el = ELIMINATED_LINE.matcher(line);
            if (el.matches()) {
                current.locks().add(new LockRef(LockRef.Kind.ELIMINATED, null, el.group("cls"),
                        current.frames().size() - 1));
                current.appendRaw(line);
                return;
            }
            // ---- "No compile task" etc. inside a block, or the blank line ending it ----
            if (trimmed.isEmpty()) {
                finishCurrent();
                return;
            }
        }

        if (trimmed.isEmpty()) return;
        if (trimmed.startsWith("JNI global ref")) { tail = true; return; }
        if (tail) return; // heap summary / GC lines after the dump body
        // Known harmless section headers we deliberately skip
        if (trimmed.startsWith("Threads class SMR info") || trimmed.startsWith("_java_thread_list")
                || trimmed.equals("}")
                || trimmed.equals("No compile task") || trimmed.startsWith("Compiling:")
                || trimmed.startsWith("Heap") || looksLikeHeapLine(trimmed)
                || trimmed.matches("(0x[0-9a-fA-F]+|\\d+)(,\\s*(0x[0-9a-fA-F]+|\\d+))*,?\\s*}?")) {
            return;
        }
        unrecognized++;
        if (firstUnrecognized == null) {
            firstUnrecognized = trimmed.length() > 120 ? trimmed.substring(0, 120) + "..." : trimmed;
        }
    }

    private boolean looksLikeHeapLine(String t) {
        return t.startsWith("PSYoungGen") || t.startsWith("ParOldGen") || t.startsWith("Metaspace")
                || t.startsWith("class space") || t.startsWith("eden space") || t.startsWith("from space")
                || t.startsWith("to   space") || t.startsWith("object space") || t.startsWith("garbage-first heap")
                || t.startsWith("region size") || t.startsWith("def new generation")
                || t.startsWith("tenured generation") || t.startsWith("compacting perm gen");
    }

    private void finishCurrent() {
        if (current != null) {
            dump.threads().add(current);
            lastThread = current;
            current = null;
        }
        inSynchronizers = false;
    }

    private void closeCycle() {
        if (cycle != null && !cycle.isEmpty()) dump.jvmDeadlockCycles().add(cycle);
        cycle = null;
        inDeadlockNames = false;
    }

    private ThreadInfo parseHeader(String name, String attrs) {
        ThreadInfo t = new ThreadInfo();
        t.setName(name);
        Matcher m = JAVA_ID.matcher(attrs);
        if (m.find()) t.setJavaId(Long.parseLong(m.group(1)));
        t.setDaemon(attrs.contains(" daemon ") || attrs.startsWith("daemon "));
        m = PRIO.matcher(attrs);
        if (m.find()) t.setPriority(Integer.parseInt(m.group(1)));
        m = OS_PRIO.matcher(attrs);
        if (m.find()) t.setOsPriority(Integer.parseInt(m.group(1)));
        m = CPU.matcher(attrs);
        if (m.find()) t.setCpuMillis(Double.parseDouble(m.group(1)));
        m = ELAPSED.matcher(attrs);
        if (m.find()) t.setElapsedSeconds(Double.parseDouble(m.group(1)));
        m = TID.matcher(attrs);
        if (m.find()) t.setTidHex(m.group(1));
        m = NID.matcher(attrs);
        if (m.find()) {
            String nid = m.group(1);
            long dec = nid.startsWith("0x") ? Long.parseLong(nid.substring(2), 16) : Long.parseLong(nid);
            t.setNid(nid.startsWith("0x") ? nid : "0x" + Long.toHexString(dec), dec);
        } else {
            m = OS_TID.matcher(attrs);
            if (m.find()) {
                long dec = Long.parseLong(m.group(1));
                t.setNid("0x" + Long.toHexString(dec), dec);
            }
        }
        m = CONDITION.matcher(attrs);
        if (m.find()) t.setHeaderCondition(m.group("cond").trim());
        return t;
    }
}
