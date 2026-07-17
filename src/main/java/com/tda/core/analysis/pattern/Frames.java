package com.tda.core.analysis.pattern;

import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Shared frame-scanning helpers for pattern heuristics. */
final class Frames {

    record Match(ThreadInfo thread, String matchedFrame) {}

    private Frames() {}

    /** Threads in one of {@code states} with any frame whose signature contains one of {@code needles}. */
    static List<Match> scan(ThreadDump dump, Set<ThreadState> states, String... needles) {
        List<Match> out = new ArrayList<>();
        for (ThreadInfo t : dump.javaThreads()) {
            if (!states.contains(t.state())) continue;
            for (StackFrame f : t.frames()) {
                String sig = f.signature();
                for (String n : needles) {
                    if (sig.contains(n)) {
                        out.add(new Match(t, f.raw()));
                        break;
                    }
                }
                if (!out.isEmpty() && out.get(out.size() - 1).thread() == t) break;
            }
        }
        return out;
    }

    /** True when one of the thread's top {@code depth} frames matches a needle. */
    static boolean topFrames(ThreadInfo t, int depth, String... needles) {
        int n = Math.min(depth, t.frames().size());
        for (int i = 0; i < n; i++) {
            String sig = t.frames().get(i).signature();
            for (String needle : needles) {
                if (sig.contains(needle)) return true;
            }
        }
        return false;
    }

    static List<String> names(List<Match> matches, int cap) {
        List<String> out = new ArrayList<>();
        for (Match m : matches) {
            if (out.size() >= cap) break;
            out.add(m.thread().name());
        }
        return out;
    }
}
