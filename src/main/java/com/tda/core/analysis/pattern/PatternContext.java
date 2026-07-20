package com.tda.core.analysis.pattern;

import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.classify.ThreadClassifier;
import com.tda.core.analysis.middleware.MiddlewareDetector;
import com.tda.core.analysis.series.PersistentLockHolders;
import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.StuckClassifier;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.model.DumpSeries;
import com.tda.core.parse.GcLogParser;

import java.util.List;

/** Everything a pattern may need, precomputed once by the engine. */
public record PatternContext(
        DumpSeries series,
        List<LockGraph> graphs,                        // one per dump, same order
        List<List<DeadlockDetector.Cycle>> deadlocks,  // one list per dump
        List<StuckClassifier.Verdict> stuckVerdicts,   // classified candidates (Rules 1-3)
        List<PersistentLockHolders.Holder> lockHolders,
        List<PoolTrend.Trend> poolTrends,
        List<GcLogParser.PauseWindow> gcPauses,        // from --gc-log; empty when absent
        List<PoolUtil> poolUtilization,                // busy/idle utilization per pool
        MiddlewareDetector.Profile middleware,         // which app server produced these dumps
        ThreadClassifier classifier,                   // idle/housekeeping classification (Rules 1-2)
        AnalysisOptions options) {

    /** Observed utilization of one pool across the series (busy = not idle-classified). */
    public record PoolUtil(String pool, double avgBusyPct, int maxSize, int blockedSeen) {}
}
