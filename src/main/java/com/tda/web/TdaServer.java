package com.tda.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.tda.core.AnalysisEngine;
import com.tda.core.AnalysisOptions;
import com.tda.core.json.Json;
import com.tda.core.json.JsonParser;
import com.tda.core.model.DumpSeries;
import com.tda.core.model.TopHSample;
import com.tda.core.parse.DumpSetLoader;
import com.tda.core.parse.TopHParser;
import com.tda.report.HtmlReport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Local web UI on the JDK's built-in HTTP server. Binds to localhost by default -
 * thread dumps are sensitive; nothing should be exposed to the network unless the
 * operator explicitly asks for it with --host.
 */
public final class TdaServer {

    private final HttpServer server;

    public TdaServer(String host, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.createContext("/", ex -> serveStatic(ex, "/web/index.html", "text/html; charset=utf-8"));
        server.createContext("/style.css", ex -> serveStatic(ex, "/web/style.css", "text/css; charset=utf-8"));
        server.createContext("/app.js", ex -> serveStatic(ex, "/web/app.js", "application/javascript; charset=utf-8"));
        server.createContext("/vendor/echarts.min.js",
                ex -> serveStatic(ex, "/web/vendor/echarts.min.js", "application/javascript; charset=utf-8"));
        server.createContext("/api/analyze", ex -> handleApi(ex, ApiKind.ANALYZE));
        server.createContext("/api/baseline", ex -> handleApi(ex, ApiKind.BASELINE));
        server.createContext("/api/report", ex -> handleApi(ex, ApiKind.REPORT));
    }

    public void start() { server.start(); }
    public void stop() { server.stop(0); }
    public int port() { return server.getAddress().getPort(); }

    private enum ApiKind { ANALYZE, BASELINE, REPORT }

    private void handleApi(HttpExchange ex, ApiKind kind) throws IOException {
        try (ex) {
            if (!"POST".equals(ex.getRequestMethod())) {
                respond(ex, 405, "text/plain", "POST only".getBytes(StandardCharsets.UTF_8));
                return;
            }
            try {
                Map<String, Object> req = JsonParser.parseObject(readBody(ex));
                Map<String, Object> result = run(req, kind);
                if (kind == ApiKind.REPORT) {
                    String html = new HtmlReport().render(result, "Thread Dump Analysis");
                    respond(ex, 200, "text/html; charset=utf-8", html.getBytes(StandardCharsets.UTF_8));
                } else {
                    respond(ex, 200, "application/json; charset=utf-8",
                            Json.write(result).getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                respond(ex, 400, "text/plain; charset=utf-8", msg.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> run(Map<String, Object> req, ApiKind kind) throws IOException {
        List<String> names = new ArrayList<>();
        List<String> contents = new ArrayList<>();
        for (Object f : (List<Object>) req.getOrDefault("files", List.of())) {
            Map<String, Object> file = (Map<String, Object>) f;
            names.add(String.valueOf(file.getOrDefault("name", "upload")));
            contents.add(String.valueOf(file.getOrDefault("content", "")));
        }
        DumpSeries series = new DumpSetLoader().loadFromStrings(names, contents);
        if (series.size() == 0) throw new IllegalArgumentException("No thread dumps found in the uploaded file(s).");

        AnalysisOptions opts = new AnalysisOptions();
        Map<String, Object> o = (Map<String, Object>) req.getOrDefault("options", Map.of());
        if (o.get("stuckK") instanceof Number n) opts.stuckK = Math.max(2, n.intValue());
        if (o.get("fingerprintDepth") instanceof Number n) opts.fingerprintDepth = Math.max(1, n.intValue());
        if (o.get("poolPatterns") instanceof Map<?, ?> pp) {
            for (Map.Entry<?, ?> e : pp.entrySet()) {
                opts.poolPatterns.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
            }
        }
        AnalysisEngine engine = new AnalysisEngine(opts);
        if (kind == ApiKind.BASELINE) return engine.buildBaseline(series);

        List<TopHSample> topH = new TopHParser().parse(String.valueOf(req.getOrDefault("top", "")));
        Map<String, Object> baseline = req.get("baseline") instanceof Map<?, ?> b
                ? (Map<String, Object>) b : null;
        return engine.analyze(series, topH, baseline);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private void serveStatic(HttpExchange ex, String resource, String contentType) throws IOException {
        try (ex; InputStream in = TdaServer.class.getResourceAsStream(resource)) {
            if (in == null) {
                respond(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
                return;
            }
            respond(ex, 200, contentType, in.readAllBytes());
        }
    }

    private static void respond(HttpExchange ex, int code, String contentType, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(body);
        }
    }
}
