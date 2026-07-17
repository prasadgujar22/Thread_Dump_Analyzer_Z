package com.tda.core.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** An ordered series of dumps (sorted by timestamp; file order is the tiebreak). */
public final class DumpSeries {
    private final List<ThreadDump> dumps = new ArrayList<>();

    public List<ThreadDump> dumps() { return dumps; }
    public int size() { return dumps.size(); }
    public ThreadDump get(int i) { return dumps.get(i); }

    public void add(ThreadDump d) { dumps.add(d); }

    /** Sorts by timestamp (dumps without one keep their relative position) and reindexes. */
    public void sortAndIndex() {
        dumps.sort(Comparator.comparing(ThreadDump::timestamp,
                Comparator.nullsLast(Comparator.naturalOrder())));
        for (int i = 0; i < dumps.size(); i++) dumps.get(i).setIndexInSeries(i);
    }
}
