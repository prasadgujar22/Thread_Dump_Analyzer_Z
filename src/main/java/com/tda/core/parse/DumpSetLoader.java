package com.tda.core.parse;

import com.tda.core.model.DumpSeries;
import com.tda.core.model.ThreadDump;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Turns files / strings into an ordered {@link DumpSeries}. */
public final class DumpSetLoader {

    private final DumpSplitter splitter = new DumpSplitter();

    /** Loads every dump found in the given files (each file may contain several dumps). */
    public DumpSeries load(List<Path> files) throws IOException {
        DumpSeries series = new DumpSeries();
        for (Path p : files) {
            String head = peek(p);
            if (JsonDumpParser.looksLikeJsonDump(head)) {
                series.add(new JsonDumpParser().parse(
                        Files.readString(p, StandardCharsets.UTF_8), p.getFileName().toString()));
                continue;
            }
            if (JavacoreParser.looksLikeJavacore(head)) {
                try (BufferedReader r = open(p)) {
                    series.add(new JavacoreParser().parse(r, p.getFileName().toString()));
                }
                continue;
            }
            try (BufferedReader r = open(p)) {
                for (ThreadDump d : splitter.split(p.getFileName().toString(), r)) series.add(d);
            }
        }
        series.sortAndIndex();
        return series;
    }

    private String peek(Path p) throws IOException {
        try (InputStream in = Files.newInputStream(p)) {
            return new String(in.readNBytes(512), StandardCharsets.UTF_8);
        }
    }

    /** Parses dumps out of in-memory content (web uploads, tests). */
    public DumpSeries loadFromStrings(List<String> names, List<String> contents) throws IOException {
        DumpSeries series = new DumpSeries();
        for (int i = 0; i < contents.size(); i++) {
            String name = i < names.size() ? names.get(i) : ("input-" + (i + 1));
            if (JsonDumpParser.looksLikeJsonDump(contents.get(i))) {
                series.add(new JsonDumpParser().parse(contents.get(i), name));
                continue;
            }
            String head = contents.get(i).substring(0, Math.min(512, contents.get(i).length()));
            if (JavacoreParser.looksLikeJavacore(head)) {
                try (BufferedReader r = new BufferedReader(new StringReader(contents.get(i)))) {
                    series.add(new JavacoreParser().parse(r, name));
                }
                continue;
            }
            try (BufferedReader r = new BufferedReader(new StringReader(contents.get(i)))) {
                for (ThreadDump d : splitter.split(name, r)) series.add(d);
            }
        }
        series.sortAndIndex();
        return series;
    }

    /** UTF-8 reader that replaces malformed bytes instead of failing (logs are rarely clean). */
    private BufferedReader open(Path p) throws IOException {
        InputStream in = Files.newInputStream(p);
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        return new BufferedReader(new InputStreamReader(in, decoder), 1 << 16);
    }
}
