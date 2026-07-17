package com.tda;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;
import com.tda.core.parse.DumpSetLoader;
import com.tda.core.parse.DumpSplitter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Test helpers for loading fixtures and parsing inline dump text. */
public final class Fixtures {

    private Fixtures() {}

    public static String read(String name) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) throw new IllegalArgumentException("missing fixture " + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static List<ThreadDump> parseAll(String text) {
        try {
            return new DumpSplitter().split("test", new BufferedReader(new StringReader(text)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static ThreadDump parseOne(String text) {
        List<ThreadDump> dumps = parseAll(text);
        if (dumps.size() != 1) throw new IllegalStateException("expected 1 dump, got " + dumps.size());
        return dumps.get(0);
    }

    public static DumpSeries series(String fixtureName) {
        try {
            DumpSeries s = new DumpSetLoader().loadFromStrings(
                    List.of(fixtureName), List.of(read(fixtureName)));
            return s;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
