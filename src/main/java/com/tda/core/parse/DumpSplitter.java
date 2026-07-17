package com.tda.core.parse;

import com.tda.core.model.ThreadDump;

import java.io.BufferedReader;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Streams a file (a raw jstack capture, or a server log with one or more {@code kill -3}
 * dumps embedded in it) line-by-line and splits out every thread-dump section it finds.
 * Never loads the whole file into memory.
 *
 * <p>Dump boundaries: a {@code Full thread dump ...} banner starts a dump; the timestamp is
 * taken from the immediately preceding {@code yyyy-MM-dd HH:mm:ss} line when present (that is
 * what jstack/jcmd/kill -3 print). A thread-header line seen while no dump is open also opens
 * one, so banner-less truncated captures still parse.
 */
public final class DumpSplitter {

    private static final Pattern TIMESTAMP = Pattern.compile(
            "^(?<ts>\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2})(?<frac>[.,]\\d{1,9})?\\b.*");
    private static final Pattern THREAD_HEADER = Pattern.compile("^\".*\"\\s+.*tid=0x[0-9a-fA-F]+.*$");
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ZoneId zone;

    public DumpSplitter() { this(ZoneId.systemDefault()); }
    public DumpSplitter(ZoneId zone) { this.zone = zone; }

    /** Parses every dump in the stream and returns them in file order. */
    public List<ThreadDump> split(String sourceName, BufferedReader reader) throws IOException {
        List<ThreadDump> out = new ArrayList<>();
        split(sourceName, reader, out::add);
        return out;
    }

    /** Streaming variant: dumps are handed to {@code sink} as soon as each one is complete. */
    public void split(String sourceName, BufferedReader reader, Consumer<ThreadDump> sink) throws IOException {
        HotSpotParser parser = new HotSpotParser();
        Instant pendingTs = null;
        int dumpNo = 0;
        String line;
        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();
            Matcher tsm = TIMESTAMP.matcher(trimmed);
            if (tsm.matches()) {
                pendingTs = parseTs(tsm.group("ts"));
                // A timestamp line is only meaningful right before a banner; if we're inside
                // a dump it usually means the dump body ended and logging resumed - but we
                // keep the dump open until we know a new one starts (cheap and safe).
                continue;
            }
            if (trimmed.startsWith("Full thread dump") || trimmed.startsWith("Full Java thread dump")) {
                if (parser.isOpen()) emit(parser, out(sink), ++dumpNo);
                parser.begin(sourceName + "#" + (dumpNo + 1), pendingTs);
                parser.accept(line);
                pendingTs = null;
                continue;
            }
            if (!parser.isOpen()) {
                if (THREAD_HEADER.matcher(trimmed).matches()) {
                    // banner-less (truncated) dump: open implicitly
                    parser.begin(sourceName + "#" + (dumpNo + 1), pendingTs);
                    parser.accept(line);
                    pendingTs = null;
                }
                continue; // ordinary log line outside any dump
            }
            parser.accept(line);
        }
        if (parser.isOpen()) emit(parser, out(sink), ++dumpNo);
    }

    private Consumer<ThreadDump> out(Consumer<ThreadDump> sink) { return sink; }

    private void emit(HotSpotParser parser, Consumer<ThreadDump> sink, int dumpNo) {
        ThreadDump d = parser.end();
        if (!d.threads().isEmpty() || !d.jvmDeadlockCycles().isEmpty()) sink.accept(d);
    }

    private Instant parseTs(String ts) {
        try {
            return LocalDateTime.parse(ts.replace('T', ' '), TS_FMT).atZone(zone).toInstant();
        } catch (Exception e) {
            return null;
        }
    }
}
