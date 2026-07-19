package com.tda;

import com.tda.core.analysis.DumpQualityValidator;
import com.tda.core.model.DumpSeries;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class QualityValidatorTest {

    private List<DumpQualityValidator.Note> notes(DumpSeries s) {
        return new DumpQualityValidator().validate(s);
    }

    private boolean has(List<DumpQualityValidator.Note> notes, String level, String contains) {
        return notes.stream().anyMatch(n -> n.level().equals(level) && n.message().contains(contains));
    }

    @Test
    void singleDumpWarnsAboutMissingComparativeAnalysis() {
        var n = notes(Fixtures.series("healthy_jdk17.txt"));
        assertTrue(has(n, "WARNING", "Single dump"), n.toString());
    }

    @Test
    void missingSynchronizerSectionsSuggestDashL() throws Exception {
        var s = new com.tda.core.parse.DumpSetLoader().loadFromStrings(List.of("x"), List.of("""
                2026-07-17 10:00:00
                Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):

                "main" #1 prio=5 os_prio=0 cpu=1.0ms elapsed=1.0s tid=0x0000000000000001 nid=0x1 runnable [0x0000000000000101]
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.A.b(A.java:1)
                """));
        assertTrue(has(notes(s), "WARNING", "without -l"));
        // and the -l fixtures must NOT warn
        var withL = notes(Fixtures.series("healthy_jdk17.txt"));
        assertTrue(withL.stream().noneMatch(x -> x.message().contains("without -l")));
    }

    @Test
    void wideGapsBetweenDumpsAreFlagged() throws Exception {
        String d = Fixtures.read("healthy_jdk17.txt");
        var s = new com.tda.core.parse.DumpSetLoader().loadFromStrings(
                List.of("a", "b"),
                List.of(d, d.replace("2026-07-10 14:03:14", "2026-07-10 14:13:14")));
        assertTrue(has(notes(s), "WARNING", "600 s apart"));
    }

    @Test
    void outOfOrderInputIsNoted() throws Exception {
        String d = Fixtures.read("healthy_jdk17.txt");
        var s = new com.tda.core.parse.DumpSetLoader().loadFromStrings(
                List.of("late", "early"),
                List.of(d.replace("2026-07-10 14:03:14", "2026-07-10 14:03:44"), d));
        assertTrue(has(notes(s), "INFO", "re-sorted"));
    }

    @Test
    void mixedJvmBannersAreFlagged() throws Exception {
        var s = new com.tda.core.parse.DumpSetLoader().loadFromStrings(
                List.of("a", "b"),
                List.of(Fixtures.read("healthy_jdk17.txt"), Fixtures.read("healthy_jdk8.txt")));
        assertTrue(has(notes(s), "WARNING", "different JVMs"));
    }

    @Test
    void clockSkewBetweenTimestampsAndElapsedIsDetected() throws Exception {
        String d1 = Fixtures.read("healthy_jdk17.txt");
        // second dump claims +10 minutes of wall clock but elapsed= only advances ~20s
        String d2 = d1.replace("2026-07-10 14:03:14", "2026-07-10 14:13:14")
                .replace("elapsed=64.68s", "elapsed=84.68s")
                .replace("elapsed=64.66s", "elapsed=84.66s")
                .replace("elapsed=63.10s", "elapsed=83.10s")
                .replace("elapsed=12.44s", "elapsed=32.44s")
                .replace("elapsed=60.01s", "elapsed=80.01s");
        var s = new com.tda.core.parse.DumpSetLoader().loadFromStrings(List.of("a", "b"), List.of(d1, d2));
        assertTrue(has(notes(s), "WARNING", "Clock skew"), notes(s).toString());
    }

    @Test
    void healthySeriesAtGoodCadenceOnlyNotesWhatIsTrue() {
        var n = notes(Fixtures.series("stuck_series_weblogic.log"));
        assertTrue(n.stream().noneMatch(x -> x.message().contains("Single dump")));
        assertTrue(n.stream().noneMatch(x -> x.message().contains("Clock skew")));
    }
}
