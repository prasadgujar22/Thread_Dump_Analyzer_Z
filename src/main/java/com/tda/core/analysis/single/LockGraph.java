package com.tda.core.analysis.single;

import com.tda.core.model.LockRef;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The wait-for graph of one dump, covering both intrinsic monitors and ownable synchronizers
 * (ReentrantLock &amp; friends, via the jstack -l synchronizer sections).
 *
 * <p>Edges are holder → waiter. A thread inside {@code Object.wait()} has <em>released</em> the
 * monitor it earlier "locked", so that address does not count as held by it.
 */
public final class LockGraph {

    /** One contended lock: who holds it and who waits for it. */
    public record Contention(String address, String lockClass, String holder, List<String> waiters) {}

    private final Map<String, ThreadInfo> holderByAddress = new HashMap<>();
    private final Map<String, LockRef> lockByAddress = new HashMap<>();
    private final Map<String, List<ThreadInfo>> waitersByAddress = new LinkedHashMap<>();
    /** waiter thread name → holder thread name (the single lock each thread can wait on). */
    private final Map<String, String> waitsFor = new LinkedHashMap<>();
    private final Map<String, ThreadInfo> byName = new HashMap<>();

    public static LockGraph build(ThreadDump dump) {
        LockGraph g = new LockGraph();
        for (ThreadInfo t : dump.threads()) {
            g.byName.put(t.name(), t);
            Set<String> released = new HashSet<>();
            LockRef waiting = t.waitingOnLock();
            if (waiting != null && waiting.kind() == LockRef.Kind.WAITING_ON) {
                released.add(waiting.address()); // Object.wait() released this monitor
            }
            for (LockRef l : t.locks()) {
                if (l.isHold() && l.address() != null && !released.contains(l.address())) {
                    g.holderByAddress.put(l.address(), t);
                    g.lockByAddress.putIfAbsent(l.address(), l);
                }
            }
        }
        for (ThreadInfo t : dump.threads()) {
            LockRef w = t.waitingOnLock();
            if (w == null) continue;
            g.lockByAddress.putIfAbsent(w.address(), w);
            g.waitersByAddress.computeIfAbsent(w.address(), k -> new ArrayList<>()).add(t);
            ThreadInfo holder = g.holderByAddress.get(w.address());
            if (holder != null && !holder.name().equals(t.name())) {
                g.waitsFor.put(t.name(), holder.name());
            }
        }
        return g;
    }

    public ThreadInfo holderOf(String address) { return holderByAddress.get(address); }
    public Map<String, String> waitsFor() { return waitsFor; }
    public ThreadInfo thread(String name) { return byName.get(name); }

    /** All locks that have at least one waiter, most-contended first. */
    public List<Contention> contendedLocks() {
        List<Contention> out = new ArrayList<>();
        for (Map.Entry<String, List<ThreadInfo>> e : waitersByAddress.entrySet()) {
            ThreadInfo holder = holderByAddress.get(e.getKey());
            LockRef ref = lockByAddress.get(e.getKey());
            List<String> waiters = e.getValue().stream().map(ThreadInfo::name).toList();
            out.add(new Contention(e.getKey(),
                    ref != null && ref.className() != null ? ref.className() : "?",
                    holder != null ? holder.name() : null, waiters));
        }
        out.sort((a, b) -> Integer.compare(b.waiters().size(), a.waiters().size()));
        return out;
    }

    /** Direct victims per holder thread name. */
    public Map<String, List<String>> directVictims() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : waitsFor.entrySet()) {
            out.computeIfAbsent(e.getValue(), k -> new ArrayList<>()).add(e.getKey());
        }
        return out;
    }

    /**
     * Direct + transitive victims per holder: how many threads would (potentially) unblock
     * if this thread released its locks. BFS over the reversed waits-for relation.
     */
    public Map<String, Integer> transitiveVictimCounts() {
        Map<String, List<String>> direct = directVictims();
        Map<String, Integer> out = new LinkedHashMap<>();
        for (String holder : direct.keySet()) {
            Set<String> seen = new HashSet<>();
            Deque<String> queue = new ArrayDeque<>(direct.get(holder));
            while (!queue.isEmpty()) {
                String v = queue.poll();
                if (!seen.add(v)) continue;
                for (String w : direct.getOrDefault(v, List.of())) {
                    if (!seen.contains(w)) queue.add(w);
                }
            }
            seen.remove(holder); // a cycle should not count the holder as its own victim
            out.put(holder, seen.size());
        }
        return out;
    }
}
