package com.tda;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DumpSplitterTest {

    @Test
    void splitsFiveDumpsOutOfOneServerLog() {
        List<ThreadDump> dumps = Fixtures.parseAll(Fixtures.read("stuck_series_weblogic.log"));
        assertEquals(5, dumps.size());
        for (ThreadDump d : dumps) {
            assertNotNull(d.timestamp(), "each dump takes the timestamp line preceding its banner");
            assertTrue(d.threads().size() >= 10);
        }
        assertTrue(dumps.get(0).timestamp().isBefore(dumps.get(4).timestamp()));
    }

    @Test
    void seriesIsSortedByTimestampNotFileOrder() {
        String late = Fixtures.read("healthy_jdk17.txt");   // 14:03:14
        String early = Fixtures.read("healthy_jdk8.txt");   // 14:03:11
        DumpSeries s;
        try {
            s = new com.tda.core.parse.DumpSetLoader()
                    .loadFromStrings(List.of("late", "early"), List.of(late, early));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        assertEquals(2, s.size());
        assertEquals("early#1", s.get(0).sourceName());
        assertEquals(0, s.get(0).indexInSeries());
    }

    @Test
    void truncatedDumpWithInterleavedLogLinesStillParses() {
        List<ThreadDump> dumps = Fixtures.parseAll(Fixtures.read("truncated_interleaved.log"));
        assertEquals(1, dumps.size());
        ThreadDump d = dumps.get(0);
        assertEquals(2, d.threads().size());
        assertEquals(3, d.threads().get(0).frames().size());
        assertFalse(d.issues().isEmpty(), "interleaved noise is reported, not fatal");
    }

    @Test
    void bannerlessCaptureOpensImplicitly() {
        List<ThreadDump> dumps = Fixtures.parseAll("""
                "w" #12 daemon prio=5 os_prio=0 tid=0x00007f0000001000 nid=0x100 runnable [0x00007f0000100000]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.Worker.spin(Worker.java:10)
                """);
        assertEquals(1, dumps.size());
        assertNull(dumps.get(0).timestamp());
        assertEquals(1, dumps.get(0).threads().size());
    }

    @Test
    void ordinaryLogFileWithNoDumpYieldsNothing() {
        assertTrue(Fixtures.parseAll("""
                2026-07-14 11:22:33 INFO starting app
                2026-07-14 11:22:34 WARN something happened
                """).isEmpty());
    }
}
