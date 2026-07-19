package com.tda.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** Tuning knobs shared by CLI and web UI. */
public final class AnalysisOptions {
    /** A thread is "stuck" when its fingerprint is unchanged for ≥ K consecutive dumps. */
    public int stuckK = 3;
    /** Number of top stack frames hashed into the cross-dump fingerprint. */
    public int fingerprintDepth = 8;
    /** How many recurring-stack groups to report per dump. */
    public int topStacks = 15;
    /** Frame cap when embedding stacks in reports. */
    public int maxFramesShown = 40;
    /** Minimum absolute growth for a pool to be flagged as a thread-leak suspect. */
    public int leakMinGrowth = 5;
    /** Threads blocked behind one holder before a finding escalates to CRITICAL (Rule 5). */
    public int criticalVictims = 5;
    /** User-defined pool rules: pool name → thread-name regex (run before built-ins). */
    public final Map<String, String> poolPatterns = new LinkedHashMap<>();

    public Map<String, Object> toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("stuckK", stuckK);
        m.put("fingerprintDepth", fingerprintDepth);
        m.put("topStacks", topStacks);
        m.put("maxFramesShown", maxFramesShown);
        m.put("leakMinGrowth", leakMinGrowth);
        m.put("criticalVictims", criticalVictims);
        if (!poolPatterns.isEmpty()) m.put("poolPatterns", new LinkedHashMap<>(poolPatterns));
        return m;
    }
}
