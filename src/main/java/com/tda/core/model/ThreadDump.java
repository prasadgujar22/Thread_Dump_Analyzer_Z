package com.tda.core.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** One complete thread dump (one "Full thread dump ..." section). */
public final class ThreadDump {
    private Instant timestamp;            // null when no timestamp line preceded the dump
    private String jvmBanner = "";        // the "Full thread dump ..." line
    private int indexInSeries;
    private String sourceName = "";
    private final List<ThreadInfo> threads = new ArrayList<>();
    private final List<List<String>> jvmDeadlockCycles = new ArrayList<>(); // thread names per reported cycle
    private final List<ParseIssue> issues = new ArrayList<>();
    private boolean sawSynchronizerSection; // dump was taken with -l (quality signal)

    public Instant timestamp() { return timestamp; }
    public void setTimestamp(Instant t) { timestamp = t; }
    public String jvmBanner() { return jvmBanner; }
    public void setJvmBanner(String b) { jvmBanner = b; }
    public int indexInSeries() { return indexInSeries; }
    public void setIndexInSeries(int i) { indexInSeries = i; }
    public String sourceName() { return sourceName; }
    public void setSourceName(String s) { sourceName = s; }
    public List<ThreadInfo> threads() { return threads; }
    public List<List<String>> jvmDeadlockCycles() { return jvmDeadlockCycles; }
    public List<ParseIssue> issues() { return issues; }
    public boolean sawSynchronizerSection() { return sawSynchronizerSection; }
    public void markSynchronizerSection() { sawSynchronizerSection = true; }

    public ThreadInfo findByName(String name) {
        for (ThreadInfo t : threads) if (t.name().equals(name)) return t;
        return null;
    }

    /** Java application threads only (excludes VM/GC/JIT threads without stacks). */
    public List<ThreadInfo> javaThreads() {
        List<ThreadInfo> out = new ArrayList<>();
        for (ThreadInfo t : threads) if (!t.isVmThread()) out.add(t);
        return out;
    }
}
