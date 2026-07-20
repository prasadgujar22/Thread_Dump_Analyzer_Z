package com.tda.core.model;

import java.util.ArrayList;
import java.util.List;

/** One thread parsed out of a dump. */
public final class ThreadInfo {
    private String name = "";
    private Long javaId;              // "#12" header field; null for VM/native threads
    private boolean daemon;
    private Integer priority;
    private Integer osPriority;
    private Double cpuMillis;         // JDK 11+ "cpu=12.5ms"; null on JDK 8 dumps
    private Double elapsedSeconds;    // JDK 11+ "elapsed=13.5s"
    private String tidHex;
    private String nidHex;
    private long nidDecimal = -1;
    private ThreadState state = ThreadState.UNKNOWN;
    private String stateDetail = "";  // full state line, e.g. "WAITING (parking)"
    private String headerCondition = ""; // e.g. "waiting on condition", "runnable" (from the header)
    private boolean virtual;          // JDK 21+ JSON dumps are the only format that shows these
    private String carrierTid;        // carrier platform-thread tid, when the dump provides it
    private final List<StackFrame> frames = new ArrayList<>();
    private final List<LockRef> locks = new ArrayList<>();
    private final StringBuilder raw = new StringBuilder();

    public String name() { return name; }
    public void setName(String v) { name = v; }
    public Long javaId() { return javaId; }
    public void setJavaId(Long v) { javaId = v; }
    public boolean isDaemon() { return daemon; }
    public void setDaemon(boolean v) { daemon = v; }
    public Integer priority() { return priority; }
    public void setPriority(Integer v) { priority = v; }
    public Integer osPriority() { return osPriority; }
    public void setOsPriority(Integer v) { osPriority = v; }
    public Double cpuMillis() { return cpuMillis; }
    public void setCpuMillis(Double v) { cpuMillis = v; }
    public Double elapsedSeconds() { return elapsedSeconds; }
    public void setElapsedSeconds(Double v) { elapsedSeconds = v; }
    public String tidHex() { return tidHex; }
    public void setTidHex(String v) { tidHex = v; }
    public String nidHex() { return nidHex; }
    public long nidDecimal() { return nidDecimal; }
    public void setNid(String hex, long decimal) { nidHex = hex; nidDecimal = decimal; }
    public ThreadState state() { return state; }
    public void setState(ThreadState v) { state = v; }
    public String stateDetail() { return stateDetail; }
    public void setStateDetail(String v) { stateDetail = v; }
    public String headerCondition() { return headerCondition; }
    public void setHeaderCondition(String v) { headerCondition = v; }
    public boolean isVirtual() { return virtual; }
    public void setVirtual(boolean v) { virtual = v; }
    public String carrierTid() { return carrierTid; }
    public void setCarrierTid(String v) { carrierTid = v; }
    public List<StackFrame> frames() { return frames; }
    public List<LockRef> locks() { return locks; }
    public void appendRaw(String line) { raw.append(line).append('\n'); }
    public String rawText() { return raw.toString(); }

    /** VM/GC/JIT threads carry no "#id" and no Java stack. */
    public boolean isVmThread() { return javaId == null && frames.isEmpty(); }

    /** Addresses of all locks this thread currently holds (monitors + ownable synchronizers). */
    public List<String> heldLockAddresses() {
        List<String> out = new ArrayList<>();
        for (LockRef l : locks) {
            if (l.isHold() && l.address() != null) out.add(l.address());
        }
        return out;
    }

    /** The lock this thread is blocked/waiting/parked on, or null. */
    public LockRef waitingOnLock() {
        for (LockRef l : locks) {
            if (l.isWait() && l.address() != null) return l;
        }
        return null;
    }

    public List<LockRef> heldLocks() {
        List<LockRef> out = new ArrayList<>();
        for (LockRef l : locks) if (l.isHold() && l.address() != null) out.add(l);
        return out;
    }

    /** FNV-1a hash of the full stack (frame signatures), used for identical-stack dedup. */
    public long stackHash() {
        return hashFrames(frames.size());
    }

    /** FNV-1a hash of the top {@code depth} frames - the comparative-analysis fingerprint. */
    public long hashFrames(int depth) {
        long h = 0xcbf29ce484222325L;
        int n = Math.min(depth, frames.size());
        for (int i = 0; i < n; i++) {
            for (byte b : frames.get(i).signature().getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
                h ^= b & 0xff;
                h *= 0x100000001b3L;
            }
            h ^= '\n';
            h *= 0x100000001b3L;
        }
        return h;
    }

    /** Stable identity for cross-dump matching: tid + name (falls back to name alone). */
    public String matchKey() {
        return (tidHex != null ? tidHex : "?") + "|" + name;
    }

    @Override public String toString() { return "\"" + name + "\" " + state; }
}
