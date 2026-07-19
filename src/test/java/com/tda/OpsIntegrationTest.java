package com.tda;

import com.sun.net.httpserver.HttpServer;
import com.tda.core.json.Json;
import com.tda.report.Redactor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase E: exit codes, webhook (the single opt-in network call), redaction. */
class OpsIntegrationTest {

    private int cli(String... args) {
        return new picocli.CommandLine(new com.tda.cli.Main()).execute(args);
    }

    // ---------------------------------------------------------------- exit codes

    @Test
    void failOnGatesTheExitCode(@TempDir Path tmp) {
        String healthy = "src/test/resources/fixtures/healthy_jdk17.txt";
        String incident = "src/test/resources/fixtures/pool_exhaustion_jdk17.txt";
        assertEquals(0, cli("analyze", healthy, "--no-history", "--fail-on", "critical"),
                "healthy dumps stay exit 0");
        assertEquals(1, cli("analyze", incident, "--no-history", "--fail-on", "critical"),
                "the CRITICAL pool-exhaustion finding must gate the pipeline");
        assertEquals(1, cli("analyze", incident, "--no-history", "--fail-on", "warning"));
        assertEquals(3, cli("analyze", tmp.resolve("empty.txt").toString(), "--no-history"),
                "unreadable/empty input is a parse failure");
        assertEquals(2, cli("analyze", "--no-history"), "missing arguments is a usage error");
    }

    // ---------------------------------------------------------------- webhook

    @Test
    void webhookPostsOnlyWhenAskedAndCarriesTheSummary(@TempDir Path tmp) throws Exception {
        AtomicReference<String> received = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", ex -> {
            received.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            ex.sendResponseHeaders(200, 0);
            ex.close();
        });
        server.start();
        try {
            String incident = "src/test/resources/fixtures/pool_exhaustion_jdk17.txt";
            // without the flag: no request must arrive
            cli("analyze", incident, "--no-history");
            assertEquals(null, received.get(), "no --webhook, no network call - ever");
            // slack format
            int exit = cli("analyze", incident, "--no-history",
                    "--webhook", "http://127.0.0.1:" + server.getAddress().getPort() + "/hook",
                    "--webhook-format", "slack");
            assertEquals(0, exit);
            assertTrue(received.get().contains("\"text\""), received.get());
            assertTrue(received.get().contains("critical: 1"), received.get());
            assertTrue(received.get().contains("waiting for a database connection"), received.get());
        } finally {
            server.stop(0);
        }
    }

    // ---------------------------------------------------------------- redaction

    @Test
    void redactionScrubsEverythingWithDeterministicPseudonyms(@TempDir Path tmp) throws Exception {
        Path json = tmp.resolve("redacted.json");
        int exit = cli("analyze", "src/test/resources/fixtures/redaction_sample.txt",
                "--no-history", "--redact", "--json", json.toString());
        assertEquals(0, exit);
        String out = Files.readString(json);
        // zero raw hosts/IPs/emails survive anywhere in the document
        assertFalse(out.contains("acme.com"), "raw hostname leaked");
        assertFalse(out.contains("app01"), "raw host label leaked");
        assertFalse(out.contains("10.20.30.40"), "raw IP leaked");
        assertFalse(out.contains("192.168.7.21"), "raw IP leaked");
        assertFalse(out.contains("mailer-ops@"), "raw email leaked");
        // pseudonyms are present and cross-references line up: the same host in two thread
        // names maps to the same pseudonym
        assertTrue(out.contains("ip-1") && out.contains("ip-2"), out.length() + " bytes");
        assertTrue(out.contains("user-1@host-1") || out.contains("user-2@host-1"),
                "thread@host tokens keep the host linkage: " + snippet(out, "user-"));
        assertTrue(out.contains("replica-host-1-monitor"),
                "app01.prod.acme.com must map to ONE pseudonym everywhere it appears");
        // and class names / frames stay intact - redaction must never mangle code identity
        assertTrue(out.contains("com.acme.orders.LedgerService.append"),
                "Java class names must never be redacted");
    }

    @Test
    void redactorIsDeterministicWithinARun() {
        Redactor r = new Redactor();
        String a = r.redact("worker@db01.prod.acme.com reading from 10.0.0.5");
        String b = r.redact("retry to db01.prod.acme.com via 10.0.0.5 and 10.0.0.6");
        assertEquals("user-1@host-1 reading from ip-1", a);
        assertEquals("retry to host-1 via ip-1 and ip-2", b,
                "the bare hostname reuses the pseudonym minted for the email's domain");
        Map<String, String> hosts = r.mappings().get("hosts");
        assertEquals(1, hosts.size());
    }

    private static String snippet(String s, String around) {
        int i = s.indexOf(around);
        return i < 0 ? "(absent)" : s.substring(Math.max(0, i - 40), Math.min(s.length(), i + 60));
    }
}
