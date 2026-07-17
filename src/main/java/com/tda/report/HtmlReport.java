package com.tda.report;

import com.tda.core.json.Json;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Renders the analysis result as a single self-contained HTML file: ECharts, the app JS,
 * the stylesheet, and the data are all inlined, so the file works offline from a file://
 * URL and can be attached to an RCA ticket as-is.
 */
public final class HtmlReport {

    public String render(Map<String, Object> analysisResult, String title) {
        String template = resource("/report/template.html");
        // literal segment-by-segment assembly; the data blob is ~MBs, so avoid regex replace
        template = replaceOnce(template, "%%TITLE%%", escapeHtml(title));
        template = replaceOnce(template, "%%CSS%%", resource("/web/style.css"));
        template = replaceOnce(template, "%%ECHARTS%%", resource("/web/vendor/echarts.min.js"));
        // Json.write escapes '<' as \u003c, so "</script>" can never appear inside the blob
        template = replaceOnce(template, "%%DATA%%", Json.write(analysisResult));
        template = replaceOnce(template, "%%APP%%", resource("/web/app.js"));
        return template;
    }

    private static String replaceOnce(String s, String needle, String replacement) {
        int i = s.indexOf(needle);
        if (i < 0) throw new IllegalStateException("template placeholder missing: " + needle);
        return s.substring(0, i) + replacement + s.substring(i + needle.length());
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static String resource(String path) {
        try (InputStream in = HtmlReport.class.getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("missing classpath resource " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read classpath resource " + path, e);
        }
    }
}
