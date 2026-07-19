# TDA Iteration 3 — Design (Capture, Correlation, Domain Intelligence, Fleet, Ops)

Per-phase design for review; implementation follows it phase by phase. Ground rules carried
forward: one shaded jar, Java 17+ runtime, JDK 8+ dumps parsed, existing design language and
section structure untouched, idle-Tomcat regression stays green after every phase. The tool
stays offline with zero telemetry; the **only** permitted network call is the explicitly
opt-in `--webhook` (Phase E).

## Phase A — Capture subsystem

### CLI

```
tda capture --pid <pid> [--count 5] [--interval 10s] [--out <dir>] [--with-top]
            [--stdout-log <path>] [--analyze]
tda watch   --pid <pid> [--cpu-threshold 80] [--thread-count-threshold N]
            [--poll 5s] [--cooldown 10m] [--out <dir>] [--exec-after <cmd>]
```

### Module layout

```
com.tda.capture
  CaptureStrategy      (interface: String describe(); String capture(pid))
  TargetJcmdStrategy   1) /proc/<pid>/exe -> the TARGET JVM's own bin/jcmd Thread.print -l
  OwnJdkStrategy       1b) our runtime's ${java.home}/bin/jcmd (same-era JVMs)
  AttachStrategy       2) com.sun.tools.attach VirtualMachine.remoteDataDump via reflection
                          (jar manifest carries Add-Opens: jdk.attach/sun.tools.attach)
  SigquitStrategy      3) kill -QUIT + print where output lands; with --stdout-log, tail
                          the log and split new dumps out of it (reuses DumpSplitter)
  CaptureSession       runs the chain once, then reuses the winning strategy for the series;
                       writes dump-NN-<ts>.txt (first line = yyyy-MM-dd HH:mm:ss timestamp,
                       exactly what the parser reads), optional top-NN.txt, manifest.json
  ProcFs               tiny readable-interface over /proc (real + fake for tests)
  Exec                 command runner abstraction (real + fake for tests)
```

`manifest.json`: `{host, pid, jvmVersion (from first dump banner), strategy, captures:[{file, time, topFile?}]}`.
`--with-top`: `top -H -b -n 1 -p <pid>` per capture point (Linux only; elsewhere a note, no failure).
End of run prints `tda analyze <dir>/*` (or runs it with `--analyze`).

### watch

Poll loop: CPU% = Δ(utime+stime from `/proc/<pid>/stat`) / Δwall / cores × 100; thread count
= entries in `/proc/<pid>/task`. Breach → full capture series (same CaptureSession) → cooldown.
Every trigger logged with the breaching metric and value. Non-Linux: clear "unsupported on
this OS" error, exit 2. `--exec-after` runs a command with the output dir as `$1`.

### Dump quality validator

`DumpQualityValidator` (core.analysis) runs on every analyze; result lands in root JSON as
`qualityNotes: [{level: INFO|WARNING, message}]`, rendered with the existing parse-notes
card at the top of the report. Checks: single-dump input; no `-l` lock detail (parser gains
a `sawSynchronizerSection` flag per dump); parse skips (existing issues surfaced here);
gaps > 60 s between dumps; out-of-order input (sorting reordered files); mixed JVM banners;
clock skew (`elapsed=` deltas vs timestamp deltas disagree > 20% and > 5 s).

## Phase B — Correlation

### GC / safepoint overlay

`GcLogParser` (core.parse) → `List<PauseWindow(startInstant, durationMs, cause, kind gc|safepoint)>`.
Formats: unified logging (`[timestamp][gc…] GC(n) Pause … 12.345ms`, `[safepoint] … Total: … ns`)
and JDK 8 (`2026-…T…: 123.4: [GC (cause) …, 0.0123 secs]`,
`Total time for which application threads were stopped: … seconds`). Tolerant line-by-line
regex; unparseable lines skipped silently.

Engine: `--gc-log <file...>` → root `gcPauses`. **Reattribution**: a stuck verdict whose
dump instants all fall inside (±2 s) pause windows is discarded with an explanatory note.
New findings: `long-gc-pause` (default > 1 s WARNING, > 5 s CRITICAL — impact is measured,
so Rule 5 is satisfied) and `frequent-safepoints` (stopped-time fraction of the capture
window > 10% → WARNING). Charts: pause windows render as shaded `markArea` bands on the
series charts (fractional category-axis coordinates interpolated from dump timestamps).

### JFR ingestion

`JfrLoader` (core.parse): `jdk.jfr.consumer.RecordingFile.readEvent()` loop — streamed,
never fully loaded. `jdk.ExecutionSample`/`jdk.NativeMethodSample` bucketed into time
slices (default 1 s, `--jfr-slice`; slice widens automatically to cap the series at ~300
synthetic dumps). Each slice becomes a synthetic `ThreadDump` (thread name/id + stack from
`RecordedStackTrace`, state RUNNABLE) fed to the unchanged comparative engine.
`jdk.ThreadPark` / `jdk.JavaMonitorEnter` aggregate into a `jfrContention` section
(monitor class, total/max duration, count); `jdk.VirtualThreadPinned` → pinning finding.
Detection: `.jfr` extension or `FLR\0` magic.

### JDK 21+ JSON format & virtual threads

`JsonDumpParser` (core.parse): `jcmd Thread.dump_to_file -format=json` documents
(`{"threadDump":{"processId","time","runtimeVersion","threadContainers":[…]}}`).
ThreadInfo gains `virtual` flag + `carrierTid` (parsed when the JSON provides `carrier`;
name defaults to `virtual-<tid>` when empty). Tiles: platform vs virtual counts; new
carrier-mapping table (carrier → virtual threads it runs); virtual parked vs runnable in
the state chart (existing states). Pinning findings come from JFR when supplied alongside.
Detection: leading `{` + `"threadDump"`.

## Phase C — Domain intelligence

### Frame→meaning knowledge base

`frame-meanings.yaml` (bundled; same override mechanics: `--frame-meanings <file>`):

```yaml
meanings:
  - name: oracle-jdbc-read
    category: db-wait
    activity: waiting on an Oracle JDBC response
    narrative: The thread sent a statement to Oracle and is blocked reading the reply.
    frames: [oracle.jdbc, oracle.net.ns, T4CPreparedStatement]
```

`FrameMeanings` (analysis.classify, parser shared with a small `YamlMini` utility) labels
every thread (first matching entry across the top 10 frames). Surfaces: `activity` +
`category` on thread rows (shown in the all-threads table and call-stack tooltips),
enriched stuck-finding evidence ("waiting on an Oracle JDBC response (db-wait) — same
statement for 3 dumps"), and a per-dump + series "Where is the time going" category
breakdown (counts per category; existing card/table styles).

### App-server name intelligence

`WlThreadName` parser: status flag, thread number, queue/work-manager name. Pools section
gains per-work-manager busy/idle utilization (busy = not idle-classified); same treatment
falls out for WebSphere `WebContainer`/`ORB.thread.pool` and Tomcat exec pools via the
existing grouping + classification.

### Rules DSL

`rules.yaml` — one schema for bundled and site rules (`--rules <file...>`, repeatable):

```yaml
rules:
  - id: mq-reply-wait-storm
    title: "{count} threads waiting on MQ replies"
    severity: warning            # cap; CRITICAL additionally requires >= criticalThreads
    criticalThreads: 10          # optional escalation threshold
    recommendation: Check the MQ manager depth and receive timeouts.
    match:
      frames: [com.ibm.mq.jmqi, MQGET]
      threadNameRegex: ".*ExecuteThread.*"   # optional
      states: [RUNNABLE, WAITING]            # optional
      minThreads: 3                          # per-dump floor
      persistDumps: 2                        # optional: matched thread keys must persist
      cpuDelta: any | zero | spinning        # optional; needs cpu= or top -H
```

`RuleEngine` implements the existing `Pattern` interface, so DSL rules and native detectors
share the findings pipeline, severity gating, and evidence blocks. **Migration boundary**
(the one deliberate scope call in this iteration): the frame-scan built-ins
(connection-pool-exhaustion, sync-logging-bottleneck, classloader-contention,
exception-processing) move onto the bundled `rules.yaml`; the graph-/cpu-theoretic
detectors (deadlock, top-blocker, stuck-classifier verdicts, thread-leak, weblogic-stuck,
network-hang, finalizer) stay native code because their logic (wait-for graphs, transitive
victim counts, fingerprint classification) is not expressible as declarative matches. Both
kinds are the same machinery from `emit` onward. CLI: `tda rules validate <file>`,
`tda rules dry-run <file> <dumps...>`.

### Pool right-sizing hints

Per pool across the series: busy (non-idle classification) vs idle vs observed max.
INFO-only hints: ≥ 90% busy with blocked/queued threads → consider increasing;
≤ 10% busy at size ≥ 20 → oversized. Never above INFO.

## Phase D — Fleet & history

### Cluster mode

`tda analyze --cluster nodeA=globA --cluster nodeB=globB …` (or `--cluster-manifest file`
with `name=glob` lines). Each node analyzed as its own series; report gains a cross-node
section: per-node state distributions side by side, pool utilization, top recurring stacks,
findings counts. Outlier scoring — deterministic, explainable: (1) any state's share
diverges > 20 pp from the fleet median; (2) a recurring stack (count ≥ 5) present on one
node and no other; (3) a pool's utilization > 30 pp from the fleet median. Output is a
sentence per outlier ("node 7 diverges: 34 threads BLOCKED on CacheManager (fleet median:
0)"). Cluster mode produces summary + outliers (no per-dump drilldown per node — documented).

### Incident memory

Embedded H2 (`com.h2database:h2`, pure Java) at `~/.tda/history.db` (`--history-db`,
`--no-history`). Tables: `analysis(id, ts, label, summary_json, baseline_json)` and
`stack(analysis_id, hash)`. After each analyze: store recurring-stack fingerprints +
findings summary + distilled baseline. Similarity = Jaccard overlap of stack-hash sets;
> 0.3 → "Similar past incidents" section (label, date, shared stacks). CLI:
`tda history list|search <text>|show <id>`. README documents that the DB contains stack
frames and is as sensitive as the dumps themselves.

### Release drift

`--label <build>` tags the stored analysis. `tda compare --baseline-label <label> <dumps…>`
loads that label's stored baseline document and reuses the existing baseline-diff engine —
"what changed since that build": new recurring stacks, state shifts, pool deltas.

## Phase E — Ops integration

- **Exit codes**: 0 clean, 1 `--fail-on critical|warning` threshold met, 2 usage error
  (picocli default), 3 parse failure (no dumps found / unreadable input).
- **Webhook** — the only network call, never fires without the flag (help text says so):
  `--webhook <url> [--webhook-format json|slack]`. json = findings summary document;
  slack = `{"text": …}` severity counts + top findings. Failures are non-fatal (warning).
- **Redaction**: `--redact` rewrites the final JSON tree (thread names, frames, lock
  strings — every string) replacing hostnames/FQDNs, IPv4s, and email-like tokens with
  deterministic first-seen pseudonyms (`host-1`, `ip-2`, `user-1@redacted`); applies to
  HTML, JSON, and webhook payloads alike. Fixture proves zero raw hosts/IPs survive.
- **Deep links & annotations**: stable anchors `#finding-<id>-<n>` and `#thread-<slug>`;
  a note field per finding/thread (localStorage in serve mode); "Export annotated report"
  re-serializes the DOM with notes inlined into a new self-contained HTML download — the
  export path works from `file://` (standalone report), which is the case that must work.

## Testing per phase (all prior fixtures stay green)

A: strategy-chain unit tests on fake ProcFs/Exec; integration test capturing a child JVM
spawned by the test; quality-validator fixtures. B: unified + JDK 8 GC fixtures incl. a
pause overlapping a dump (reattribution asserted); in-test `jdk.jfr.Recording`; JSON
fixture with virtual threads + carriers. C: rules validate/dry-run + one custom rule
end-to-end; meanings labels asserted. D: fleet fixture with a seeded outlier (explanation
string asserted); history similarity + `--no-history` leaves no db. E: exit codes;
redaction fixture (no raw host/IP survives; pseudonyms deterministic).
