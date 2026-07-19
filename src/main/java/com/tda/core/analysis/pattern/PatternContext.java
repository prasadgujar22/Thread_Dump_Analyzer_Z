package com.tda.core.analysis.pattern;

import com.tda.core.AnalysisOptions;
import com.tda.core.analysis.series.PersistentLockHolders;
import com.tda.core.analysis.series.PoolTrend;
import com.tda.core.analysis.series.StuckClassifier;
import com.tda.core.analysis.single.DeadlockDetector;
import com.tda.core.analysis.single.LockGraph;
import com.tda.core.model.DumpSeries;

import java.util.List;

/** Everything a pattern may need, precomputed once by the engine. */
public record PatternContext(
        DumpSeries series,
        List<LockGraph> graphs,                        // one per dump, same order
        List<List<DeadlockDetector.Cycle>> deadlocks,  // one list per dump
        List<StuckClassifier.Verdict> stuckVerdicts,   // classified candidates (Rules 1-3)
        List<PersistentLockHolders.Holder> lockHolders,
        List<PoolTrend.Trend> poolTrends,
        AnalysisOptions options) {
}
