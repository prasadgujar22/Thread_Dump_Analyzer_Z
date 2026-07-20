package com.tda.capture;

import java.io.PrintStream;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.function.LongSupplier;

/**
 * Trigger-based auto-capture: polls process CPU%% and thread count from /proc, fires a
 * capture series on breach, then honors a cooldown to prevent capture storms. Extracted
 * from the CLI so the trigger logic is unit-testable with a fake ProcFs and clock.
 */
public final class WatchLoop {

    /** Fired on breach; receives a human-readable trigger reason. */
    public interface TriggerAction {
        void fire(String reason) throws Exception;
    }

    private final ProcFs proc;
    private final PrintStream log;
    private final LongSupplier nanoClock;

    private Long prevTicks;
    private long prevNanos;
    private Instant cooldownUntil = Instant.MIN;

    public WatchLoop(ProcFs proc, PrintStream log, LongSupplier nanoClock) {
        this.proc = proc;
        this.log = log;
        this.nanoClock = nanoClock;
    }

    /**
     * One poll step. Returns the trigger reason when a threshold was breached (and fires
     * the action), or null. Pure function of /proc samples so tests can drive it directly.
     */
    public String poll(long pid, Double cpuThreshold, Integer threadThreshold,
                       Duration cooldown, TriggerAction action) throws Exception {
        long nowNanos = nanoClock.getAsLong();
        String reason = null;

        if (cpuThreshold != null) {
            OptionalLong ticks = proc.cpuTicks(pid);
            if (ticks.isPresent()) {
                if (prevTicks != null && nowNanos > prevNanos) {
                    double wallSec = (nowNanos - prevNanos) / 1e9;
                    double cpuSec = (ticks.getAsLong() - prevTicks) / (double) proc.ticksPerSecond();
                    double pct = 100.0 * cpuSec / wallSec / Math.max(1, proc.cpuCores());
                    if (pct >= cpuThreshold) {
                        reason = String.format("cpu %.1f%% >= threshold %.1f%%", pct, cpuThreshold);
                    }
                }
                prevTicks = ticks.getAsLong();
                prevNanos = nowNanos;
            }
        }
        if (reason == null && threadThreshold != null) {
            OptionalInt count = proc.threadCount(pid);
            if (count.isPresent() && count.getAsInt() >= threadThreshold) {
                reason = "thread count " + count.getAsInt() + " >= threshold " + threadThreshold;
            }
        }

        if (reason == null) return null;
        Instant now = Instant.ofEpochSecond(0, nowNanos);
        if (now.isBefore(cooldownUntil)) {
            log.println("trigger suppressed by cooldown: " + reason);
            return null;
        }
        log.println("TRIGGER: " + reason);
        action.fire(reason);
        cooldownUntil = now.plus(cooldown);
        return reason;
    }
}
