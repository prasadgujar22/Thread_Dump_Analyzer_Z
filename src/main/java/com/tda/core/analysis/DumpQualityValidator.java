package com.tda.core.analysis;

import com.tda.core.analysis.series.SeriesIndex;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.ParseIssue;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dump-quality validation, run on every analyze. Notes are advisory (INFO/WARNING) and
 * rendered with the existing parse-notes card - bad input should degrade the analysis
 * gracefully and SAY SO, never silently produce weaker findings.
 */
public final class DumpQualityValidator {

    public record Note(String level, String message) {}

    public List<Note> validate(DumpSeries series) {
        List<Note> out = new ArrayList<>();
        if (series.size() == 0) return out;

        if (series.size() == 1) {
            out.add(new Note("WARNING", "Single dump: comparative analysis (stuck threads, "
                    + "trends, persistence) is unavailable. Capture 3-5 dumps 10-30 s apart - "
                    + "`tda capture --pid <pid>` does this in one command."));
        }

        boolean anySync = false;
        Set<String> banners = new LinkedHashSet<>();
        int parseIssues = 0;
        for (ThreadDump d : series.dumps()) {
            anySync |= d.sawSynchronizerSection();
            if (!d.jvmBanner().isEmpty()) banners.add(d.jvmBanner());
            parseIssues += d.issues().size();
        }
        if (!anySync) {
            out.add(new Note("WARNING", "No 'Locked ownable synchronizers' sections found - "
                    + "these dumps were taken without -l, so ReentrantLock and other "
                    + "java.util.concurrent lock ownership is invisible. Use `jstack -l` or "
                    + "`jcmd <pid> Thread.print -l`."));
        }
        if (parseIssues > 0) {
            int shown = 0;
            for (ThreadDump d : series.dumps()) {
                for (ParseIssue i : d.issues()) {
                    if (shown++ >= 5) break;
                    out.add(new Note("INFO", "Parse: " + i));
                }
            }
            if (parseIssues > 5) {
                out.add(new Note("INFO", "Parse: " + (parseIssues - 5) + " further note(s) omitted"));
            }
        }
        if (banners.size() > 1) {
            out.add(new Note("WARNING", "Dumps come from " + banners.size() + " different JVMs ("
                    + String.join(" | ", banners) + ") - series comparisons across different "
                    + "processes are not meaningful. Analyze per node, or use --cluster."));
        }
        if (series.wasReordered()) {
            out.add(new Note("INFO", "Input files were not in timestamp order; the series was "
                    + "re-sorted by each dump's own timestamp."));
        }
        for (int i = 1; i < series.size(); i++) {
            var a = series.get(i - 1).timestamp();
            var b = series.get(i).timestamp();
            if (a != null && b != null) {
                long gap = Duration.between(a, b).getSeconds();
                if (gap > 60) {
                    out.add(new Note("WARNING", "Dumps " + (i - 1) + " and " + i + " are " + gap
                            + " s apart - stuck/trend detection works best at 10-30 s intervals; "
                            + "state changes between distant snapshots go unseen."));
                }
            }
        }
        checkClockSkew(series, out);
        return out;
    }

    /** elapsed= deltas disagreeing with timestamp deltas means somebody's clock lies. */
    private void checkClockSkew(DumpSeries series, List<Note> out) {
        if (series.size() < 2) return;
        SeriesIndex index = SeriesIndex.build(series);
        for (int i = 1; i < series.size(); i++) {
            var a = series.get(i - 1).timestamp();
            var b = series.get(i).timestamp();
            if (a == null || b == null) continue;
            double wall = Duration.between(a, b).toMillis() / 1000.0;
            if (wall <= 0) continue;
            List<Double> deltas = new ArrayList<>();
            for (Map.Entry<String, ThreadInfo[]> e : index.occurrences().entrySet()) {
                ThreadInfo p = e.getValue()[i - 1];
                ThreadInfo c = e.getValue()[i];
                if (p != null && c != null && p.elapsedSeconds() != null && c.elapsedSeconds() != null) {
                    deltas.add(c.elapsedSeconds() - p.elapsedSeconds());
                }
            }
            if (deltas.size() < 3) continue;
            deltas.sort(Double::compare);
            double median = deltas.get(deltas.size() / 2);
            double diff = Math.abs(median - wall);
            if (diff > 5 && diff > 0.2 * wall) {
                out.add(new Note("WARNING", String.format(
                        "Clock skew between dumps %d and %d: timestamps advance %.1f s but "
                        + "thread elapsed= fields advance %.1f s - one of the clocks is wrong; "
                        + "trust the elapsed-based ordering with caution.", i - 1, i, wall, median)));
                return; // one skew note is enough
            }
        }
    }
}
