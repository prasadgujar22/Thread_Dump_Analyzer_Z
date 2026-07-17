package com.tda;

import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.json.Json;
import com.tda.core.json.JsonParser;
import com.tda.core.model.DumpSeries;
import com.tda.core.parse.TopHParser;
import com.tda.report.HtmlReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Fixture series → analysis → JSON + self-contained HTML report, verified on disk. */
class EndToEndTest {

    @TempDir
    Path tmp;

    @Test
    void weblogicIncidentSeriesToHtmlReport() throws IOException {
        DumpSeries series = Fixtures.series("stuck_series_weblogic.log");
        assertEquals(5, series.size());

        AnalysisEngine engine = new AnalysisEngine(new AnalysisOptions());
        Map<String, Object> result = engine.analyze(series,
                new TopHParser().parse(Fixtures.read("top_h_sample.txt")));

        // JSON artifact: must be valid and carry every top-level section
        Path json = tmp.resolve("analysis.json");
        Files.writeString(json, Json.write(result), StandardCharsets.UTF_8);
        Map<String, Object> back = JsonParser.parseObject(Files.readString(json));
        assertTrue(back.containsKey("dumps"));
        assertTrue(back.containsKey("series"));
        assertTrue(back.containsKey("findings"));
        assertEquals(5, ((List<?>) back.get("dumps")).size());
        assertFalse(((List<?>) back.get("findings")).isEmpty());

        // HTML artifact: single self-contained file - data, app and ECharts inlined, no CDN refs
        Path html = tmp.resolve("report.html");
        Files.writeString(html, new HtmlReport().render(result, "e2e"), StandardCharsets.UTF_8);
        String content = Files.readString(html);
        assertTrue(content.contains("tda-data"));
        assertTrue(content.contains("TDA.render"));
        assertTrue(content.contains("Apache ECharts") || content.contains("echarts"));
        assertTrue(content.contains("frozenFrames"));
        assertFalse(content.matches("(?s).*(src|href)=[\"']https?://.*"),
                "the report must never reference the network");
        assertTrue(Files.size(html) > 1_000_000, "ECharts must actually be inlined");
    }

    @Test
    void largeSyntheticDumpParsesFast() throws IOException {
        // 5,000 threads in one dump - must parse in well under a second per NFRs
        StringBuilder sb = new StringBuilder(1 << 22);
        sb.append("2026-07-15 10:00:00\n");
        sb.append("Full thread dump OpenJDK 64-Bit Server VM (17.0.11+9-LTS mixed mode, sharing):\n\n");
        for (int i = 0; i < 5000; i++) {
            sb.append("\"http-nio-8080-exec-").append(i).append("\" #").append(i + 10)
              .append(" daemon prio=5 os_prio=0 cpu=1.0ms elapsed=9.0s tid=0x")
              .append(String.format("%016x", 0x7f0000000000L + i * 0x1000L))
              .append(" nid=0x").append(Long.toHexString(0x1000 + i))
              .append(" waiting on condition  [0x0000000000000000]\n")
              .append("   java.lang.Thread.State: WAITING (parking)\n")
              .append("\tat jdk.internal.misc.Unsafe.park(java.base@17.0.11/Native Method)\n")
              .append("\tat java.util.concurrent.locks.LockSupport.park(java.base@17.0.11/LockSupport.java:341)\n")
              .append("\tat java.util.concurrent.LinkedBlockingQueue.take(java.base@17.0.11/LinkedBlockingQueue.java:435)\n")
              .append("\tat java.lang.Thread.run(java.base@17.0.11/Thread.java:840)\n\n");
        }
        long t0 = System.nanoTime();
        DumpSeries series;
        try {
            series = new com.tda.core.parse.DumpSetLoader()
                    .loadFromStrings(List.of("big"), List.of(sb.toString()));
        } finally {
            // timing asserted below; parse itself must not throw
        }
        long parseMs = (System.nanoTime() - t0) / 1_000_000;
        assertEquals(5000, series.get(0).threads().size());

        t0 = System.nanoTime();
        Map<String, Object> result = new AnalysisEngine(new AnalysisOptions()).analyze(series, List.of());
        long analyzeMs = (System.nanoTime() - t0) / 1_000_000;
        assertEquals(5000, ((Map<?, ?>) ((List<?>) result.get("dumps")).get(0)).get("totalThreads"));
        assertTrue(parseMs < 5000, "parse took " + parseMs + "ms");
        assertTrue(analyzeMs < 10000, "analysis took " + analyzeMs + "ms");
    }
}
