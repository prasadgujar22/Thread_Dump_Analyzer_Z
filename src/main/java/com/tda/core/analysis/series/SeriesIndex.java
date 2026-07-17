package com.tda.core.analysis.series;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Matches threads across the dumps of a series by tid + name.
 *
 * <p>The WebLogic status prefix ({@code [ACTIVE]}/{@code [STUCK]}/{@code [STANDBY]}/{@code [HOGGING]})
 * is stripped before matching - WebLogic rewrites it as thread health changes, and losing the
 * match on exactly the threads that just became STUCK would defeat the whole analysis.
 */
public final class SeriesIndex {

    private static final Pattern WL_STATUS = Pattern.compile("^\\[(STUCK|ACTIVE|STANDBY|HOGGING)] ");

    private final int dumpCount;
    private final Map<String, ThreadInfo[]> byKey = new LinkedHashMap<>();

    private SeriesIndex(int dumpCount) { this.dumpCount = dumpCount; }

    public static String normalizedName(String name) {
        return WL_STATUS.matcher(name).replaceFirst("");
    }

    public static String keyOf(ThreadInfo t) {
        return (t.tidHex() != null ? t.tidHex() : "?") + "|" + normalizedName(t.name());
    }

    public static SeriesIndex build(DumpSeries series) {
        SeriesIndex idx = new SeriesIndex(series.size());
        for (int i = 0; i < series.size(); i++) {
            ThreadDump d = series.get(i);
            for (ThreadInfo t : d.threads()) {
                ThreadInfo[] arr = idx.byKey.computeIfAbsent(keyOf(t),
                        k -> new ThreadInfo[idx.dumpCount]);
                arr[i] = t;
            }
        }
        return idx;
    }

    public int dumpCount() { return dumpCount; }

    /** Matched occurrences per key, first-seen order; array slots are null where absent. */
    public Map<String, ThreadInfo[]> occurrences() { return byKey; }

    /** Display name for a key: normalized name of its first occurrence. */
    public String displayName(String key) {
        ThreadInfo[] arr = byKey.get(key);
        if (arr != null) {
            for (ThreadInfo t : arr) if (t != null) return normalizedName(t.name());
        }
        int bar = key.indexOf('|');
        return bar >= 0 ? key.substring(bar + 1) : key;
    }

    /** Latest (last-dump) occurrence for a key, or null. */
    public ThreadInfo latest(String key) {
        ThreadInfo[] arr = byKey.get(key);
        if (arr == null) return null;
        for (int i = arr.length - 1; i >= 0; i--) if (arr[i] != null) return arr[i];
        return null;
    }

    public List<String> keys() { return new ArrayList<>(byKey.keySet()); }
}
