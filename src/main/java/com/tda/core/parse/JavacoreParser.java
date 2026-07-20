package com.tda.core.parse;

import com.tda.core.model.LockRef;
import com.tda.core.model.ParseIssue;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.io.BufferedReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses IBM J9 / Eclipse OpenJ9 javacore files - the thread-dump format produced by
 * IBM JDKs (traditional WebSphere) and IBM Semeru, written on {@code kill -3},
 * {@code wsadmin} dump requests, hung-thread detection, and OOM events.
 *
 * <p>Javacore is a tagged line format ({@code 0SECTION}, {@code 3XMTHREADINFO},
 * {@code 4XESTACKTRACE}, ...). The sections used here:
 * <ul>
 *   <li><b>TITLE</b>: {@code 1TIDATETIME} timestamp, {@code 1TISIGINFO} dump reason</li>
 *   <li><b>ENVINFO</b>: {@code 1CIJAVAVERSION} for the JVM banner</li>
 *   <li><b>LOCKS</b>: the monitor pool dump ({@code 2LKMONINUSE}/{@code 3LKMONOBJECT}
 *       with owner, {@code 3LKWAITER} blocked entrants, {@code 3LKWAITNOTIFY} waiters)
 *       and the JVM's own {@code 1LKDEADLOCK} report</li>
 *   <li><b>THREADS</b>: {@code 3XMTHREADINFO} headers (name, J9 state, priority),
 *       {@code 3XMJAVALTHREAD} (java id, daemon), {@code 3XMTHREADINFO1} (native tid),
 *       {@code 3XMCPUTIME} per-thread CPU, {@code 3XMTHREADBLOCK} (blocked/waiting/parked
 *       on which object owned by whom), {@code 4XESTACKTRACE} frames and
 *       {@code 5XESTACKTRACE (entered lock: ...)} held-monitor annotations</li>
 * </ul>
 *
 * <p>Class names use {@code /} separators in javacore; they are normalized to {@code .}
 * so fingerprints, idle patterns, and rules match the same code across JVM vendors.
 * Lock addresses are normalized to lowercase {@code 0x...} strings so the existing
 * {@code LockGraph}/deadlock analyses work unchanged.
 */
public final class JavacoreParser {

    /** Cheap sniff on the first bytes of a file: javacores open with tagged NULL/0SECTION lines. */
    public static boolean looksLikeJavacore(String head) {
        return head.contains("0SECTION") || head.contains("1TISIGINFO") || head.contains("NULL           ---");
    }

    // 3XMTHREADINFO      "WebContainer : 0" J9VMThread:0x..., omrthread_t:0x..., java/lang/Thread:0x..., state:CW, prio=5
    private static final Pattern THREAD_INFO = Pattern.compile(
            "^3XMTHREADINFO\\s+\"(?<name>.*)\"\\s+(?<attrs>.*)$");
    private static final Pattern J9VMTHREAD = Pattern.compile("J9VMThread:(0x[0-9a-fA-F]+)");
    private static final Pattern STATE = Pattern.compile("state:([A-Z]+)");
    private static final Pattern PRIO = Pattern.compile("prio=(\\d+)");
    // 3XMJAVALTHREAD            (java/lang/Thread getId:0x1, isDaemon:false)
    private static final Pattern JAVAL_THREAD = Pattern.compile(
            "^3XMJAVALTHREAD\\s+\\(java/lang/Thread getId:0x([0-9a-fA-F]+), isDaemon:(true|false)\\)");
    // 3XMTHREADINFO1            (native thread ID:0x3039, native priority:0x5, ...)
    private static final Pattern NATIVE_ID = Pattern.compile("native thread ID:(0x[0-9a-fA-F]+|\\d+)");
    // 3XMCPUTIME               CPU usage total: 12.345678900 secs, user: ...
    private static final Pattern CPU_TIME = Pattern.compile(
            "^3XMCPUTIME\\s+.*?CPU usage total:\\s*([\\d.]+)\\s*secs");
    // 4XESTACKTRACE                at java/lang/Object.waitImpl(Native Method)
    private static final Pattern STACK_LINE = Pattern.compile("^4XESTACKTRACE\\s+(?<frame>at\\s+.*)$");
    // 5XESTACKTRACE                   (entered lock: com/x/Foo@0x00000000E0001234, entry count: 1)
    private static final Pattern ENTERED_LOCK = Pattern.compile(
            "^5XESTACKTRACE\\s+\\(entered lock:\\s*(?<obj>[^,@]+)@(?<addr>0x[0-9a-fA-F]+)(?:/[0-9a-fA-Fx]+)?,\\s*entry count:\\s*\\d+\\)");
    // 3XMTHREADBLOCK     Blocked on: com/x/Foo@0x... Owned by: "Thread-2" (J9VMThread:0x..., java/lang/Thread:0x...)
    private static final Pattern THREAD_BLOCK = Pattern.compile(
            "^3XMTHREADBLOCK\\s+(?<verb>Blocked|Waiting|Parked)\\s+on:\\s*(?<obj><unknown>|[^@\\s]+@0x[0-9a-fA-F]+)"
            + "(?:\\s+Owned by:\\s*(?<owner>\"[^\"]*\"|<unowned>|<unknown>).*)?$");
    // 3LKMONOBJECT       com/x/Foo@0x00000000E0001234: owner "Thread-1" (0x123), entry count 2
    //                    java/lang/String@0x...: Flat locked by "X" (0x...), entry count 1
    //                    java/lang/Object@0x...: <unowned>
    private static final Pattern MON_OBJECT = Pattern.compile(
            "^3LKMONOBJECT\\s+(?<cls>[^@\\s]+)@(?<addr>0x[0-9a-fA-F]+)(?:/[0-9a-fA-Fx]+)?:\\s*(?<rest>.*)$");
    private static final Pattern MON_OWNER = Pattern.compile(
            "(?:owner|Flat locked by)\\s+\"(?<owner>[^\"]*)\"");
    // 3LKWAITER                "Thread-2" (0x234)   /   3LKWAITNOTIFY            "Thread-3" (0x345)
    private static final Pattern LK_WAITER = Pattern.compile(
            "^3LK(?<kind>WAITER|WAITNOTIFY)\\s+\"(?<name>[^\"]*)\".*$");
    // 2LKDEADLOCKTHR  Thread "DeadLockThread 0" (0x41DAB100)
    private static final Pattern DEADLOCK_THR = Pattern.compile(
            "^2LKDEADLOCKTHR\\s+Thread\\s+\"(?<name>[^\"]*)\".*$");
    // 1TIDATETIME    Date: 2024/03/15 at 10:23:45:123  (older files omit the millis)
    private static final Pattern DATETIME = Pattern.compile(
            "^1TIDATETIME(?<utc>UTC)?\\s+Date:\\s*(?<date>\\d{4}/\\d{2}/\\d{2}) at (?<time>\\d{2}:\\d{2}:\\d{2})(?::(?<ms>\\d{1,3}))?.*$");
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

    private final ZoneId zone;

    public JavacoreParser() { this(ZoneId.systemDefault()); }
    public JavacoreParser(ZoneId zone) { this.zone = zone; }

    /** State collected from the LOCKS monitor pool dump, applied to threads after the pass. */
    private record MonitorFacts(Map<String, LockOwner> heldBy, Map<String, List<Waiter>> waiters) {}
    private record LockOwner(String threadName, String address, String className) {}
    private record Waiter(String threadName, LockRef.Kind kind) {}

    public ThreadDump parse(BufferedReader reader, String sourceName) throws IOException {
        ThreadDump dump = new ThreadDump();
        dump.setSourceName(sourceName);

        Map<String, LockOwner> owners = new LinkedHashMap<>();          // addr -> owner
        Map<String, List<Waiter>> waiters = new LinkedHashMap<>();      // addr -> waiters
        Map<String, String> lockClasses = new LinkedHashMap<>();        // addr -> class fqn
        List<List<String>> deadlockCycles = new ArrayList<>();

        ThreadInfo current = null;
        boolean inJavaStack = false;       // between "Java callstack:" and the next non-stack tag
        String monAddr = null;             // 3LKMONOBJECT currently collecting waiters
        List<String> deadlockCycle = null;
        String dumpReason = null;
        String javaVersion = null;
        boolean utcTimestamp = false;
        boolean sawLocksSection = false;
        boolean sawThreadsSection = false;
        int unrecognized = 0;
        String firstUnrecognized = null;

        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty() || line.startsWith("NULL")) continue;

            String tag = tagOf(line);
            switch (tag) {
                case "1TIDATETIME", "1TIDATETIMEUTC" -> {
                    Matcher m = DATETIME.matcher(line);
                    if (m.matches() && (dump.timestamp() == null || m.group("utc") != null)) {
                        utcTimestamp = m.group("utc") != null;
                        try {
                            LocalDateTime ldt = LocalDateTime.parse(
                                    m.group("date") + " " + m.group("time"), TS_FMT);
                            if (m.group("ms") != null) {
                                ldt = ldt.plusNanos(Long.parseLong(m.group("ms")) * 1_000_000L);
                            }
                            dump.setTimestamp(ldt.atZone(utcTimestamp ? ZoneOffset.UTC : zone).toInstant());
                        } catch (Exception ignored) { /* keep null */ }
                    }
                }
                case "1TISIGINFO" -> dumpReason = line.substring(tag.length()).trim();
                case "1CIJAVAVERSION" -> javaVersion = line.substring(tag.length()).trim();
                case "2XMFULLTHDDUMP" -> {
                    String banner = line.substring(tag.length()).trim();
                    if (dump.jvmBanner().isEmpty()) dump.setJvmBanner(banner);
                }

                // ---- LOCKS: monitor pool dump ----
                case "1LKMONPOOLDUMP", "1LKPOOLINFO" -> sawLocksSection = true;
                case "2LKMONINUSE" -> monAddr = null;
                case "3LKMONOBJECT" -> {
                    Matcher m = MON_OBJECT.matcher(line.stripTrailing());
                    if (m.matches()) {
                        monAddr = normAddr(m.group("addr"));
                        String cls = normClass(m.group("cls"));
                        lockClasses.put(monAddr, cls);
                        Matcher ow = MON_OWNER.matcher(m.group("rest"));
                        if (ow.find()) owners.put(monAddr, new LockOwner(ow.group("owner"), monAddr, cls));
                    } else {
                        monAddr = null;
                    }
                }
                case "3LKWAITERQ", "3LKNOTIFYQ" -> { /* queue headers; entries follow */ }
                case "3LKWAITER", "3LKWAITNOTIFY" -> {
                    Matcher m = LK_WAITER.matcher(line.stripTrailing());
                    if (m.matches() && monAddr != null) {
                        LockRef.Kind kind = "WAITER".equals(m.group("kind"))
                                ? LockRef.Kind.WAITING_TO_LOCK : LockRef.Kind.WAITING_ON;
                        waiters.computeIfAbsent(monAddr, k -> new ArrayList<>())
                                .add(new Waiter(m.group("name"), kind));
                    }
                }

                // ---- LOCKS: the JVM's own deadlock report ----
                case "1LKDEADLOCK" -> {
                    if (deadlockCycle != null && deadlockCycle.size() >= 2) deadlockCycles.add(deadlockCycle);
                    deadlockCycle = new ArrayList<>();
                }
                case "2LKDEADLOCKTHR" -> {
                    Matcher m = DEADLOCK_THR.matcher(line.stripTrailing());
                    if (m.matches() && deadlockCycle != null && !deadlockCycle.contains(m.group("name"))) {
                        deadlockCycle.add(m.group("name"));
                    }
                }

                // ---- THREADS ----
                case "1XMCURTHDINFO", "1XMTHDINFO" -> sawThreadsSection = true;
                case "3XMTHREADINFO" -> {
                    finish(dump, current);
                    inJavaStack = false;
                    current = null;
                    Matcher m = THREAD_INFO.matcher(line.stripTrailing());
                    if (m.matches()) {
                        current = new ThreadInfo();
                        current.setName(m.group("name"));
                        String attrs = m.group("attrs");
                        Matcher a = J9VMTHREAD.matcher(attrs);
                        if (a.find()) current.setTidHex(a.group(1).toLowerCase());
                        a = STATE.matcher(attrs);
                        if (a.find()) {
                            current.setState(mapState(a.group(1)));
                            current.setStateDetail(stateLabel(a.group(1)));
                        }
                        a = PRIO.matcher(attrs);
                        if (a.find()) current.setPriority(Integer.parseInt(a.group(1)));
                        current.appendRaw(line);
                    }
                    // "Anonymous native thread" and similar unnamed entries are skipped
                }
                case "3XMJAVALTHREAD" -> {
                    Matcher m = JAVAL_THREAD.matcher(line.stripTrailing());
                    if (current != null && m.lookingAt()) {
                        current.setJavaId(Long.parseLong(m.group(1), 16));
                        current.setDaemon(Boolean.parseBoolean(m.group(2)));
                    }
                }
                case "3XMTHREADINFO1" -> {
                    if (current != null) {
                        Matcher m = NATIVE_ID.matcher(line);
                        if (m.find()) {
                            String nid = m.group(1);
                            long dec = nid.startsWith("0x")
                                    ? Long.parseLong(nid.substring(2), 16) : Long.parseLong(nid);
                            current.setNid("0x" + Long.toHexString(dec), dec);
                        }
                    }
                }
                case "3XMCPUTIME" -> {
                    if (current != null) {
                        Matcher m = CPU_TIME.matcher(line.stripTrailing());
                        if (m.lookingAt()) {
                            current.setCpuMillis(Double.parseDouble(m.group(1)) * 1000.0);
                        }
                    }
                }
                case "3XMTHREADBLOCK" -> {
                    if (current != null) {
                        Matcher m = THREAD_BLOCK.matcher(line.stripTrailing());
                        if (m.matches() && !"<unknown>".equals(m.group("obj"))) {
                            int at = m.group("obj").indexOf('@');
                            String cls = normClass(m.group("obj").substring(0, at));
                            String addr = normAddr(m.group("obj").substring(at + 1));
                            lockClasses.putIfAbsent(addr, cls);
                            LockRef.Kind kind = switch (m.group("verb")) {
                                case "Blocked" -> LockRef.Kind.WAITING_TO_LOCK;
                                case "Parked" -> LockRef.Kind.PARKING_TO_WAIT_FOR;
                                default -> LockRef.Kind.WAITING_ON;
                            };
                            current.locks().add(new LockRef(kind, addr, cls, -1));
                            String owner = m.group("owner");
                            if (owner != null && owner.startsWith("\"")) {
                                owners.putIfAbsent(addr, new LockOwner(
                                        owner.substring(1, owner.length() - 1), addr, cls));
                            }
                        }
                        current.appendRaw(line);
                    }
                }
                case "3XMTHREADINFO3" -> {
                    inJavaStack = current != null && line.contains("Java callstack");
                }
                case "4XESTACKTRACE" -> {
                    if (current != null && inJavaStack) {
                        Matcher m = STACK_LINE.matcher(line.stripTrailing());
                        if (m.matches()) {
                            StackFrame f = StackFrame.parse(normalizeFrame(m.group("frame")));
                            if (f != null) {
                                current.frames().add(f);
                                current.appendRaw("\tat " + f.raw());
                            }
                        }
                    }
                }
                case "5XESTACKTRACE" -> {
                    if (current != null && inJavaStack) {
                        Matcher m = ENTERED_LOCK.matcher(line.trim());
                        if (m.lookingAt()) {
                            String addr = normAddr(m.group("addr"));
                            String cls = normClass(m.group("obj").trim());
                            lockClasses.putIfAbsent(addr, cls);
                            current.locks().add(new LockRef(LockRef.Kind.LOCKED_MONITOR, addr, cls,
                                    current.frames().size() - 1));
                            owners.putIfAbsent(addr, new LockOwner(current.name(), addr, cls));
                            current.appendRaw(line.trim());
                        }
                    }
                }
                case "4XENATIVESTACK", "3XMTHREADINFO2", "3XMHEAPALLOC", "5XENATIVESTACK" -> { /* skipped */ }
                default -> {
                    // Tagged lines from sections we don't analyze (MEMINFO, CLASSES, GPINFO ...)
                    // are expected; only untagged garbage counts as unrecognized.
                    if (!line.isBlank() && !line.matches("^\\d[A-Z]{2,}.*")) {
                        unrecognized++;
                        if (firstUnrecognized == null) {
                            String t = line.trim();
                            firstUnrecognized = t.length() > 120 ? t.substring(0, 120) + "..." : t;
                        }
                    }
                }
            }
        }
        finish(dump, current);
        if (deadlockCycle != null && deadlockCycle.size() >= 2) deadlockCycles.add(deadlockCycle);
        dump.jvmDeadlockCycles().addAll(deadlockCycles);

        applyMonitorFacts(dump, new MonitorFacts(owners, waiters), lockClasses);

        if (dump.jvmBanner().isEmpty()) {
            dump.setJvmBanner("IBM J9/OpenJ9 javacore"
                    + (javaVersion != null ? " - " + javaVersion : ""));
        }
        if (sawLocksSection) dump.markSynchronizerSection(); // LOCKS gives full ownership; no -l concept
        if (dumpReason != null) {
            dump.setDumpReason(dumpReason);
            dump.issues().add(new ParseIssue(sourceName, "javacore dump event: " + dumpReason));
        }
        if (!sawThreadsSection && dump.threads().isEmpty()) {
            dump.issues().add(new ParseIssue(sourceName, "no THREADS section found in javacore"));
        }
        if (unrecognized > 0) {
            dump.issues().add(new ParseIssue(sourceName, unrecognized
                    + " unrecognized line(s) skipped (first: \"" + firstUnrecognized + "\")"));
        }
        return dump;
    }

    /** The leading tag token of a javacore line, e.g. "3XMTHREADINFO". */
    private static String tagOf(String line) {
        int i = 0;
        while (i < line.length() && !Character.isWhitespace(line.charAt(i))) i++;
        return line.substring(0, i);
    }

    private static void finish(ThreadDump dump, ThreadInfo t) {
        if (t != null) dump.threads().add(t);
    }

    /**
     * Merges LOCKS-section ownership into the parsed threads: the owner of each in-use
     * monitor gets a LOCKED_MONITOR hold, each queued entrant a WAITING_TO_LOCK, and each
     * wait()-er a WAITING_ON - deduplicated against annotations already read per thread.
     */
    private static void applyMonitorFacts(ThreadDump dump, MonitorFacts facts,
                                          Map<String, String> lockClasses) {
        Map<String, ThreadInfo> byName = new LinkedHashMap<>();
        for (ThreadInfo t : dump.threads()) byName.putIfAbsent(t.name(), t);

        for (Map.Entry<String, LockOwner> e : facts.heldBy().entrySet()) {
            ThreadInfo owner = byName.get(e.getValue().threadName());
            if (owner != null && !hasLock(owner, LockRef.Kind.LOCKED_MONITOR, e.getKey())) {
                owner.locks().add(new LockRef(LockRef.Kind.LOCKED_MONITOR, e.getKey(),
                        lockClasses.get(e.getKey()), -1));
            }
        }
        for (Map.Entry<String, List<Waiter>> e : facts.waiters().entrySet()) {
            for (Waiter w : e.getValue()) {
                ThreadInfo t = byName.get(w.threadName());
                if (t != null && !hasLock(t, w.kind(), e.getKey())) {
                    t.locks().add(new LockRef(w.kind(), e.getKey(), lockClasses.get(e.getKey()), -1));
                }
            }
        }
    }

    private static boolean hasLock(ThreadInfo t, LockRef.Kind kind, String addr) {
        for (LockRef l : t.locks()) {
            if (l.kind() == kind && addr.equals(l.address())) return true;
        }
        return false;
    }

    /**
     * J9 thread states: R (runnable), CW (condition wait: Object.wait/sleep/join),
     * B (blocked on a monitor), P (parked on a j.u.c synchronizer), S (suspended),
     * Z (dead), N (not started), MW (monitor wait - pre-J9 IBM JVMs).
     */
    static ThreadState mapState(String j9) {
        return switch (j9) {
            case "R" -> ThreadState.RUNNABLE;
            case "B", "MW" -> ThreadState.BLOCKED;
            case "CW", "P", "S" -> ThreadState.WAITING;
            case "Z" -> ThreadState.TERMINATED;
            case "N" -> ThreadState.NEW;
            default -> ThreadState.UNKNOWN;
        };
    }

    private static String stateLabel(String j9) {
        return switch (j9) {
            case "R" -> "RUNNABLE (J9 state R)";
            case "B" -> "BLOCKED (J9 state B, on monitor enter)";
            case "MW" -> "BLOCKED (J9 state MW, monitor wait)";
            case "CW" -> "WAITING (J9 state CW, condition wait)";
            case "P" -> "WAITING (J9 state P, parked)";
            case "S" -> "WAITING (J9 state S, suspended)";
            case "Z" -> "TERMINATED (J9 state Z)";
            case "N" -> "NEW (J9 state N)";
            default -> "UNKNOWN (J9 state " + j9 + ")";
        };
    }

    /**
     * Normalizes a javacore frame line to HotSpot shape:
     * {@code at java/lang/Thread.sleep(Thread.java:340(Compiled Code))}
     * becomes {@code at java.lang.Thread.sleep(Thread.java:340)}.
     */
    public static String normalizeFrame(String frame) {
        String f = frame.trim();
        int paren = f.indexOf('(');
        if (paren < 0) return f;
        String sig = f.substring(0, paren).replace('/', '.');
        String loc = f.substring(paren + 1);
        int close = loc.lastIndexOf(')');
        if (close >= 0) loc = loc.substring(0, close);
        loc = loc.replace("(Compiled Code)", "").replace("(JIT Compiled Code)", "").trim();
        // "Bytecode PC:123" and similar J9-only location decorations reduce to the source ref
        int inner = loc.indexOf('(');
        if (inner > 0) loc = loc.substring(0, inner).trim();
        return sig + "(" + loc + ")";
    }

    private static String normClass(String cls) { return cls.replace('/', '.'); }

    private static String normAddr(String addr) { return addr.toLowerCase(); }
}
