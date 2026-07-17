package com.tda.core.parse;

import com.tda.core.model.TopHSample;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Parses pasted {@code top -H [-p pid]} output. The PID column of {@code top -H} is the OS
 * thread id, which equals the {@code nid} in a HotSpot dump (in decimal) - joining the two
 * gives per-Java-thread CPU on JDK 8 dumps that have no {@code cpu=} header field.
 */
public final class TopHParser {

    public List<TopHSample> parse(String text) {
        List<TopHSample> out = new ArrayList<>();
        if (text == null || text.isBlank()) return out;
        int pidIdx = -1, cpuIdx = -1, memIdx = -1, cmdIdx = -1;
        for (String line : text.split("\r?\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            List<String> tok = Arrays.asList(t.split("\\s+"));
            if (tok.contains("PID") && tok.contains("%CPU")) { // header row - learn column order
                pidIdx = tok.indexOf("PID");
                cpuIdx = tok.indexOf("%CPU");
                memIdx = tok.indexOf("%MEM");
                cmdIdx = tok.indexOf("COMMAND");
                continue;
            }
            if (pidIdx < 0 || tok.size() <= Math.max(pidIdx, cpuIdx)) continue;
            try {
                long pid = Long.parseLong(tok.get(pidIdx));
                double cpu = Double.parseDouble(tok.get(cpuIdx).replace(',', '.'));
                double mem = memIdx >= 0 && memIdx < tok.size()
                        ? parseOrZero(tok.get(memIdx)) : 0.0;
                String cmd = cmdIdx >= 0 && cmdIdx < tok.size()
                        ? String.join(" ", tok.subList(cmdIdx, tok.size())) : "";
                out.add(new TopHSample(pid, cpu, mem, cmd));
            } catch (NumberFormatException ignored) {
                // summary rows ("%Cpu(s): ...", "MiB Mem :") and other noise
            }
        }
        return out;
    }

    private double parseOrZero(String s) {
        try { return Double.parseDouble(s.replace(',', '.')); } catch (NumberFormatException e) { return 0; }
    }
}
