# TDA — Enterprise Thread Dump Analyzer: Design

This document is the up-front design proposal (data model + module layout) requested in the
project brief. The implementation follows it; deviations, if any become necessary, are listed
at the bottom under "Deviations".

## Goals recap

* Single shaded jar (`tda.jar`), Java 17+ runtime, fully offline (no CDN, no telemetry).
* Two modes: `analyze <files...>` (CLI → JSON + self-contained HTML) and `serve [--port]` (local web UI).
* First-class HotSpot `jstack` / `jcmd Thread.print` parsing for JDK 8 **and** JDK 11/17/21 formats,
  including dumps embedded in server logs (`kill -3`).
* Single-dump analysis, comparative series analysis (stuck threads, lock persistence, pool trends,
  baseline diff), and a pattern library that emits severity-ranked findings with remediation.

## Module layout

One Maven module, but strict package boundaries (parser → model → analyzers → renderers).
`com.tda.core.*` has **zero** web/CLI dependencies and is reusable as a library.

```
com.tda
├── core
│   ├── model          # immutable-ish data model, no logic beyond accessors/derivations
│   │     ThreadState, StackFrame, LockRef, LockRefKind, ThreadInfo,
│   │     ThreadDump, DumpSeries, TopHSample, ParseIssue
│   ├── parse          # text → model (streaming, tolerant)
│   │     DumpSplitter        - splits a log/stream into dump sections, auto-detects boundaries
│   │     HotSpotParser       - parses one dump section (JDK 8 and 11+ header variants)
│   │     TopHParser          - parses pasted `top -H` output (nid ↔ %CPU join)
│   │     DumpSetLoader       - files/streams → ordered DumpSeries (sorted by timestamp)
│   ├── analysis
│   │   ├── single     # per-dump analyzers
│   │   │     StateDistribution, LockGraph (monitors + ownable synchronizers),
│   │   │     DeadlockDetector (JVM report + independent wait-for cycle detection),
│   │   │     StackDeduplicator (stack-hash groups), PoolGrouper (built-in + user regex),
│   │   │     CpuAttribution (cpu=/elapsed= fields + top -H join)
│   │   ├── series     # cross-dump analyzers
│   │   │     ThreadMatcher (tid+name), StackFingerprint (top-N frame hash, N configurable),
│   │   │     StuckThreadDetector (same fingerprint ≥K consecutive dumps, RUNNABLE/BLOCKED),
│   │   │     TransitionTimeline, PersistentLockHolders, PoolTrend (monotonic growth flag),
│   │   │     BaselineDiff (healthy series vs incident series)
│   │   └── pattern    # pattern library → findings
│   │         Pattern (interface), Finding, Severity, Evidence,
│   │         DeadlockPattern, ConnectionPoolExhaustionPattern, SyncLoggingPattern,
│   │         NetworkHangPattern, ClassloaderContentionPattern, FinalizerBacklogPattern,
│   │         WebLogicStuckPattern, TopBlockerPattern, ThreadLeakPattern, StuckThreadPattern
│   ├── AnalysisEngine # orchestrates: DumpSeries (+options, +top -H, +baseline) → AnalysisResult
│   └── json           # dependency-free JSON writer (Json, JsonWriter) — keeps the jar small
├── report             # AnalysisResult → artifacts
│     JsonReport       - canonical machine-readable output
│     HtmlReport       - single self-contained file: inlined ECharts + app JS + data
├── web                # jdk com.sun.net.httpserver; serves the bundled UI + /api/analyze
│     TdaServer, ApiHandler, StaticHandler
└── cli                # picocli
      Main, AnalyzeCommand, ServeCommand
```

Frontend (classpath resources, no CDN):

```
src/main/resources/web/
  index.html  app.js  style.css  vendor/echarts.min.js   # served by `serve`, inlined by HtmlReport
src/main/resources/report/template.html                  # skeleton for the standalone report
```

## Data model

```java
enum ThreadState { NEW, RUNNABLE, BLOCKED, WAITING, TIMED_WAITING, TERMINATED, UNKNOWN }

enum LockRefKind {
  LOCKED_MONITOR,        // "- locked <0x…> (a Foo)"
  WAITING_TO_LOCK,       // "- waiting to lock <0x…>"     → BLOCKED on monitor
  WAITING_ON,            // "- waiting on <0x…>"          → Object.wait()
  PARKING_TO_WAIT_FOR,   // "- parking to wait for <0x…>" → j.u.c. parked
  LOCKED_SYNCHRONIZER,   // "Locked ownable synchronizers:" entries (jstack -l)
  ELIMINATED             // "- eliminated <owner is scalar replaced>"
}

record StackFrame(String raw, String classFqn, String method, String location, boolean nativeMethod)
record LockRef(LockRefKind kind, String address /*0x… or null*/, String className)

class ThreadInfo {
  String  name;              // exact, e.g. "[STUCK] ExecuteThread: '12' for queue: '…'"
  Long    javaId;            // "#12" (null for VM threads)
  boolean daemon;
  Integer priority, osPriority;
  Double  cpuMillis, elapsedMillis;   // JDK 11+ only; null on JDK 8 dumps
  String  tidHex;            // 0x00007f…
  String  nidHex;  long nidDecimal;   // both representations kept
  ThreadState state;         // UNKNOWN for VM/GC/JIT threads without a Java stack
  String  stateDetail;       // e.g. "WAITING (parking)"; header condition for VM threads
  List<StackFrame> frames;
  List<LockRef> locks;       // all lock refs in stack order + synchronizer section
  String  rawText;           // original block, for evidence rendering
  // derived: waitingOnAddress(), lockedAddresses(), isVmThread(), stackHash()
}

class ThreadDump {
  Instant timestamp;          // from the line preceding "Full thread dump"; else file order
  String  jvmBanner;          // "Full thread dump OpenJDK 64-Bit Server VM (25.302-b08 …)"
  int     indexInSeries;
  List<ThreadInfo> threads;
  List<List<String>> jvmDeadlockCycles; // thread names from "Found one Java-level deadlock"
  List<ParseIssue> issues;    // skipped/truncated sections — reported, never fatal
  String  sourceName;         // file it came from
}

class DumpSeries { List<ThreadDump> dumps /* timestamp-ordered */; }
record TopHSample(long pid /* == nid decimal */, double cpuPercent, String command)
record ParseIssue(String where, String message)
```

### Analysis result (what reports/UI consume)

`AnalysisEngine` produces one `AnalysisResult`:

* per-dump: state distribution, dedup stack groups, pool table, lock graph edges, deadlocks,
  CPU table (cpu= delta and/or top -H)
* series: matched-thread timelines, stuck threads (with frozen frames as evidence),
  persistent lock holders (+ cumulative starved count), pool trends, baseline diff (optional)
* findings: `List<Finding>` — `severity ∈ {CRITICAL, WARNING, INFO}`, evidence
  (thread names, frames, dump indices), concrete recommendation, sorted by severity

The whole result serializes to one JSON document; the HTML report and the web UI are the same
JS app reading that JSON (report inlines it, web UI fetches it from `/api/analyze`).

## Parsing strategy

* **Streaming**: `DumpSplitter` consumes a `BufferedReader` line-by-line (never loads the file);
  a dump section starts at a timestamp line immediately preceding `Full thread dump` (or a bare
  `Full thread dump` for truncated logs) and ends at the next boundary/EOF. Non-dump log lines
  outside sections are discarded; unparseable lines inside a section are recorded as `ParseIssue`.
* **Header regex** tolerates both variants (and JDK 19+ decimal nids / `[os_tid]` brackets):
  `"name" [#id] [daemon] [prio=N] [os_prio=N] [cpu=…ms] [elapsed=…s] tid=0x… nid=(0x…|N) <condition> [0x…]`
  plus headerless VM threads (`"VM Thread" os_prio=0 tid=… nid=… runnable`).
* Deadlock report, `Locked ownable synchronizers:`, `JNI global ref…` sections handled explicitly.
* Series ordering: dump timestamp; fallback = file order given on the CLI.

## Key algorithm notes

* **Lock graph**: `address → holder` from LOCKED_MONITOR/LOCKED_SYNCHRONIZER; edges
  holder → each thread with WAITING_TO_LOCK / PARKING_TO_WAIT_FOR / WAITING_ON that address.
  Top blocker = max (direct + transitive) victims via BFS.
* **Deadlock (independent)**: cycle detection (iterative DFS) over thread → holder(waited lock).
* **Fingerprint**: FNV-1a over the top N frame signatures (default N=8, `--fingerprint-depth`).
* **Stuck**: same fingerprint for ≥K consecutive dumps (default 3, `--stuck-k`) while
  RUNNABLE or BLOCKED in each. WebLogic `[STUCK]`/hogging name markers are separate findings.
* **Persistent lock holder**: monitor addresses can move between dumps (GC), so identity is
  (holder thread, lock class) with the address shown per dump; starved count = distinct waiters
  accumulated across the series.
* **Thread leak suspect**: per-pool counts strictly non-decreasing with ≥ configurable growth.
* **Baseline**: `--baseline-save baseline.json` persists distilled stats of a healthy series;
  `--baseline baseline.json` diffs the incident series against it.

## Dependencies (runtime)

| Dep | Why |
|---|---|
| picocli | CLI parsing (spec requirement) |
| *(none else)* | HTTP = JDK `com.sun.net.httpserver`; JSON = tiny built-in writer; charts = bundled ECharts |

Tests: JUnit 5. Fixtures under `src/test/resources/fixtures/` in both JDK 8 and JDK 17/21
formats: healthy, JVM-reported deadlock, connection-pool exhaustion, 5-dump stuck series
(WebLogic-style names incl. `[STUCK]`), log-embedded multi-dump file.

## Phasing

1. **Phase 1**: model + parser + single-dump analyzers + CLI `analyze` (JSON + basic HTML).
2. **Phase 2**: series analyzers + baseline mode; CLI grows the series/baseline flags.
3. **Phase 3**: pattern library + full findings, charts (stacked states bar, pool-trend lines,
   RUNNABLE flame/icicle, collapsible blocker tree, per-thread swimlanes), `serve` web UI, README.

The CLI is usable at the end of every phase; each phase lands as at least one commit.

## Deviations

None.
