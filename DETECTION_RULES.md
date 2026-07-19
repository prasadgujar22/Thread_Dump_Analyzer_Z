# TDA Detection Rules (iteration 2)

The iteration-1 stuck-thread heuristic ("unchanged top-N fingerprint across ≥K dumps while
RUNNABLE/BLOCKED ⇒ CRITICAL") fired on idle Tomcat's `main` (StandardServer.await accept
loop) and on `Reference Handler` (native wait reported as RUNNABLE). This document is the
revised rule set. Rules apply in precedence order; the first classification wins.

## Rule table

| # | Rule | Inputs | Classification | Max severity |
|---|------|--------|----------------|--------------|
| 1 | **Idle-pattern knowledge base** — any of the top 5 frames matches a known "waiting for work/events" pattern (substring match, module prefixes and line numbers ignored) | thread stack; `idle-patterns.yaml` (classpath) + optional `--idle-patterns` override file | `idle` with the pattern's label, e.g. "idle (acceptor/await loop)" | none (never a finding; visible as classification in the threads table) |
| 2 | **JVM housekeeping allowlist** — thread name matches `Reference Handler`, `Finalizer`, `Signal Dispatcher`, `Attach Listener`, `Common-Cleaner`, `Notification Thread`, `Service Thread`, `Monitor Deflation Thread`, `C1/C2 CompilerThread*`, `Sweeper thread`, `VM Thread`, `VM Periodic Task Thread`, GC/G1/ZGC/Shenandoah workers, `Cleaner-*` | thread name | `housekeeping` | none — **exception:** housekeeping thread BLOCKED on an application-owned monitor (e.g. Finalizer stalled) is a real finding | exception: WARNING |
| 3a | **CPU-delta corroboration, idle native wait** — persistent RUNNABLE fingerprint, cpuΔ ≈ 0 (< 5% of wall clock and < 100 ms) while wall clock advanced, top frame native | `cpu=` per dump (JDK 11+), dump timestamps; `top -H` %CPU as source on JDK 8 | `idle-native-wait` | INFO |
| 3b | **CPU-delta corroboration, spinning** — persistent RUNNABLE fingerprint, cpuΔ ≥ 70% of wall clock | same | `spinning` (busy-wait / infinite loop) | WARNING; **CRITICAL** if it also holds a lock with waiters |
| 3c | **JDK 8 fallback** (no `cpu=`, no `top -H`) — persistent RUNNABLE fingerprint flags only if it matches no idle pattern AND (belongs to a recognized worker pool OR has application frames — non-JDK, non-container packages — in its stack) | stack, pool grouping | `stuck-candidate`, confidence *medium* (vs *high* with CPU evidence) | WARNING |
| 3d | **Frozen BLOCKED** — persistent BLOCKED fingerprint on the same monitor with a visible live holder | lock graph per dump | `blocked-chain` | scales with victims (Rule 5) |
| 4 | **Persistent lock holder requires victims** — reported only when ≥1 thread waits on that lock in ≥1 dump (in practice TDA requires contention in ≥2 consecutive dumps). A lock held across all dumps with zero waiters is by-design ownership | lock graph series | holder finding or nothing | per Rule 5 |
| 5 | **Severity gating** — CRITICAL needs demonstrable impact: deadlock cycle; ≥ N victims behind one holder (default 5, `--critical-victims`); pool at/near max with blocked work; spinning thread that blocks others. Pattern matches without impact cap at WARNING | all of the above | – | gate on every finding |

Every finding carries an **evidence block**: frames, dump indices, cpu deltas + wall-clock
deltas, victim counts, a one-line "why this is not a false positive", and a **confidence**
level (high / medium / low). Threads reclassified idle/housekeeping are also removed from
the swimlane's "stuck" flags.

## Idle-pattern file format

Bundled at `idle-patterns.yaml` on the classpath; users extend/override with
`--idle-patterns <file>` (entries are appended and match first). The format is a strict,
dependency-free YAML subset — two-space indentation, `#` comments:

```yaml
# Threads whose top frames match any listed frame substring are classified idle.
patterns:
  - name: socket-accept            # unique id (user file overrides same-name entries)
    label: idle (acceptor/await loop)
    frames:                        # substring match against frame signatures,
      - sun.nio.ch.Net.accept      # top 5 frames of the stack are examined
      - sun.nio.ch.NioSocketImpl.accept
      - java.net.PlainSocketImpl.socketAccept
      - java.net.ServerSocket.accept
  - name: selector-wait
    label: idle (selector/poller wait)
    frames:
      - sun.nio.ch.EPoll.wait
      - sun.nio.ch.EPollArrayWrapper.epollWait
      - sun.nio.ch.KQueue.poll
      - sun.nio.ch.WEPoll.wait
      - sun.nio.ch.Net.poll
      - WindowsSelectorImpl$SubSelector.poll0
  - name: reference-processing
    label: idle (reference processing)
    frames:
      - java.lang.ref.Reference.waitForReferencePendingList
  - name: executor-idle
    label: idle (waiting for work)
    frames:
      - java.util.concurrent.ThreadPoolExecutor.getTask
      - ScheduledThreadPoolExecutor$DelayedWorkQueue.take
      - java.util.concurrent.LinkedBlockingQueue.take
      - java.util.concurrent.LinkedBlockingQueue.poll
      - java.util.concurrent.LinkedBlockingDeque.takeFirst
      - java.util.concurrent.ForkJoinPool.awaitWork
      - java.util.concurrent.ForkJoinPool.scan
  - name: container-idle
    label: idle (container idle loop)
    frames:
      - org.apache.catalina.core.StandardServer.await
      - org.apache.tomcat.util.net.NioEndpoint$Poller.run
      - org.apache.tomcat.util.net.Acceptor.run
      - weblogic.work.ExecuteThread.waitForRequest
      - weblogic.socket.PosixSocketMuxer.processSockets
      - weblogic.socket.SocketMuxer.processSockets
```

Matching is substring-based on the frame signature (`class.method`), so JDK module
prefixes (`java.base@21.0.11/…`) and line numbers never break it. A `SynchronousQueue`
poll/take only counts as idle when it appears under `ThreadPoolExecutor.getTask`
(covered by the `executor-idle` entry, since `getTask` is within the top frames).

## Regression fixtures

1. `fixtures/idle-tomcat-jdk21/TD1–3.txt` — idle vanilla Tomcat on JDK 21, dumps 20–29 s
   apart (`main` cpu=731.66 ms constant). Asserts **zero CRITICAL, zero WARNING**; `main`
   idle (acceptor/await loop); `Reference Handler` housekeeping.
2. Synthetic true positive — RUNNABLE on identical app frames, `cpu=` advancing ≈ wall
   clock. Asserts the spinning finding still fires.
3. Synthetic blocked chain — 6 threads BLOCKED behind one persistent holder. Asserts
   CRITICAL with victim count.
4. JDK 8-format variants of 1 and 2 (no `cpu=`) exercising the 3c fallback.
