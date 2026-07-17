package com.tda.core.analysis.series;

import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Long-running/stuck detection: a thread whose stack fingerprint (hash of the top N frames)
 * is unchanged across ≥ K consecutive dumps while RUNNABLE or BLOCKED in every one of them.
 * The frozen frames are captured as evidence.
 */
public final class StuckThreadDetector {

    public record Stuck(String key, String name, String tid, int fromDump, int toDump,
                        List<String> states, List<String> frozenFrames, String fingerprint) {
        public int runLength() { return toDump - fromDump + 1; }
    }

    private final int k;
    private final int fingerprintDepth;
    private final int maxFramesShown;

    public StuckThreadDetector(int k, int fingerprintDepth, int maxFramesShown) {
        this.k = Math.max(2, k);
        this.fingerprintDepth = fingerprintDepth;
        this.maxFramesShown = maxFramesShown;
    }

    public List<Stuck> detect(SeriesIndex index) {
        List<Stuck> out = new ArrayList<>();
        for (Map.Entry<String, ThreadInfo[]> e : index.occurrences().entrySet()) {
            ThreadInfo[] occ = e.getValue();
            int runStart = -1;
            Long runFp = null;
            for (int i = 0; i <= occ.length; i++) {
                ThreadInfo t = i < occ.length ? occ[i] : null;
                boolean eligible = t != null && !t.frames().isEmpty()
                        && (t.state() == ThreadState.RUNNABLE || t.state() == ThreadState.BLOCKED);
                Long fp = eligible ? t.hashFrames(fingerprintDepth) : null;
                if (fp != null && fp.equals(runFp)) continue; // run continues
                if (runFp != null && i - runStart >= k) {
                    out.add(toStuck(e.getKey(), index, occ, runStart, i - 1, runFp));
                }
                runStart = fp != null ? i : -1;
                runFp = fp;
            }
        }
        out.sort((a, b) -> Integer.compare(b.runLength(), a.runLength()));
        return out;
    }

    private Stuck toStuck(String key, SeriesIndex index, ThreadInfo[] occ, int from, int to, long fp) {
        Set<String> states = new LinkedHashSet<>();
        for (int i = from; i <= to; i++) states.add(occ[i].state().name());
        ThreadInfo last = occ[to];
        List<String> frames = new ArrayList<>();
        for (StackFrame f : last.frames()) {
            if (frames.size() >= maxFramesShown) break;
            frames.add(f.raw());
        }
        return new Stuck(key, index.displayName(key), last.tidHex(), from, to,
                new ArrayList<>(states), frames, Long.toHexString(fp));
    }
}
