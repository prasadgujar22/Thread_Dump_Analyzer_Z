# TDA — Enterprise Thread Dump Analyzer

An offline thread-dump analyzer for middleware engineers (WebLogic, WebSphere, Tomcat,
JBoss/WildFly) diagnosing production incidents. Ingests one dump or an ordered series,
compares dumps against each other, detects long-running/stuck threads, and produces
severity-ranked findings with concrete remediation steps — as an interactive local web UI,
a self-contained HTML report, and JSON for automation.

**Everything runs locally.** One jar, no installer, no external database, no telemetry, no
CDN. Dumps contain production data; they never leave the machine. The single exception is
the explicitly opt-in `--webhook` flag (see Ops integration) — without it, zero network
calls, ever.

## Quick start

```bash
mvn package                     # -> target/tda.jar (the only artifact you need)

# CLI: analyze a series, produce JSON + a self-contained HTML report
java -jar tda.jar analyze dump1.txt dump2.txt dump3.txt --json out.json --html report.html

# Web UI: drag-and-drop dumps in the browser (localhost only by default)
java -jar tda.jar serve --port 8080
```

Requires Java 17+ to run (builds against release 17; tested on 21).

## Capturing thread dumps

The comparative analysis is the interesting part — always capture a **series**, not a single
snapshot. The built-in capture subsystem does this in one command:

```bash
java -jar tda.jar capture --pid <pid>                    # 5 dumps, 10 s apart, + manifest.json
java -jar tda.jar capture --pid <pid> --with-top --analyze   # + top -H per capture, report in one shot
```

The capture strategy is an ordered fallback chain (cross-version attach is unreliable):
the **target JVM's own jcmd** resolved via `/proc/<pid>/exe` (a JDK 8 WebLogic is dumped by
JDK 8's jcmd — no attach-protocol mismatch), our runtime's jcmd, the Attach API, and finally
SIGQUIT — with `--stdout-log <path>` TDA tails the target's stdout log and splits the dumps
out of it. Output files are analysis-ready (leading timestamp line) plus a `manifest.json`
(host, pid, JVM version, capture times, strategy used). Linux-first; `--with-top` degrades
gracefully elsewhere.

**Trigger-based auto-capture** (Linux only — reads /proc):

```bash
java -jar tda.jar watch --pid <pid> --cpu-threshold 80 --thread-count-threshold 900 \
     --poll 5s --cooldown 10m --exec-after ./notify.sh
```

Breaches fire a full capture series (logged with the breaching metric), then honor the
cooldown; `--exec-after` receives the output directory as its argument.

Manual capture still works, of course:

```bash
PID=$(jcmd -l | grep MyServer | cut -d' ' -f1)
for i in 1 2 3 4 5; do
  jcmd $PID Thread.print -l >> dumps-$(hostname).txt   # or: jstack -l $PID
  sleep 10
done

# optional but valuable on JDK 8 (no cpu= in dump headers): per-thread CPU from the OS
top -H -b -n 1 -p $PID > top-h.txt
```

Notes:

* `jstack -l` / `jcmd Thread.print -l` include the *locked ownable synchronizers* sections —
  without `-l` you lose ReentrantLock visibility.
* `kill -3 <pid>` works too; the dump goes to the server's stdout log. TDA finds and splits
  dumps embedded in server logs automatically (multiple dumps per file are fine — that's the
  normal WebLogic/Tomcat case).
* JDK 8 through 21 dump formats are all first-class; `cpu=`/`elapsed=` header fields
  (JDK 11+) are used when present.
* **IBM J9 / OpenJ9 javacores** (traditional WebSphere on IBM JDK, IBM Semeru) are
  first-class too: `javacore.*.txt` files are auto-detected and parsed - THREADS with
  J9 states and per-thread CPU (`3XMCPUTIME`), the LOCKS monitor pool (owners, blocked
  entrants, wait()-ers), `1LKDEADLOCK` reports, `3XMTHREADBLOCK` blocked/parked
  annotations, and the `1TISIGINFO` dump reason (an OOM-triggered javacore becomes a
  CRITICAL finding). Frames are normalized to HotSpot shape so fingerprints, idle
  patterns, and rules match identically across JVM vendors; a series of javacores
  (WAS writes three on hung-thread detection) flows through the same comparative
  pipeline as jstack series.
* Appending all dumps to one file (as above) is fine; passing five separate files is fine
  too. The series is ordered by each dump's own timestamp.
* Every analyze runs a **dump-quality validator**: single-dump input, missing `-l` lock
  detail, parse skips, >60 s gaps, out-of-order files, mixed JVMs, and clock skew
  (`elapsed=` vs timestamps) surface as INFO/WARNING notes at the top of the report.

## Correlating with other JVM signals

* **GC/safepoint overlay** — `--gc-log <file>` (unified logging or JDK 8
  `PrintGCDetails`): pause windows render as shaded bands on the series charts; a frozen
  thread whose whole run coincides with pause windows is **reattributed to the pause**, not
  the application; long pauses (>1 s WARNING, >5 s CRITICAL) and frequent safepoints (>10%
  stopped time) become findings with the cause.
* **JFR** — `tda analyze recording.jfr` streams `jdk.ExecutionSample` events into
  time-sliced synthetic dumps (default 1 s, `--jfr-slice`) fed to the same engine: same
  findings and charts with hundreds of data points. `jdk.ThreadPark`/`jdk.JavaMonitorEnter`
  aggregate into a lock-contention section; `jdk.VirtualThreadPinned` becomes a finding.
* **JDK 21+ JSON dumps** — `jcmd <pid> Thread.dump_to_file -format=json` is the only format
  with virtual threads: platform/virtual tiles, carrier→virtual mapping table, parked vs
  runnable in the state charts.

## Domain intelligence

* **Middleware detection**: every analysis identifies the app server (WebLogic /
  WebSphere traditional / Liberty / Tomcat / WildFly) from thread-name shapes, frame
  packages, and the JVM banner - deterministic, weighted, with the evidence shown in a
  "Server profile" section together with a per-dump busy/total health table of that
  server's worker groups (WebLogic queues, Tomcat connectors, WAS/Liberty pools).
  Detection gates the platform analyzers below so WebLogic heuristics never fire on a
  Tomcat dump.
* **Platform health analyzers** (findings with evidence + remediation, like everything
  else):
  - *WebLogic*: self-tuning **thread starvation** (every execute thread busy, zero
    STANDBY reserve - fires before WLS's own 600 s [STUCK] verdict), **socket muxer
    BLOCKED** (front end stops reading requests), plus rule-pack detectors for JTA
    commit stalls, t3/RMI peer hangs, and LDAP authentication stalls.
  - *Tomcat*: **connector exhaustion** (all `-exec-` workers busy = maxThreads wall;
    acceptCount queueing explained), **Poller/Acceptor BLOCKED** (no new I/O reaches the
    exec pool), **ContainerBackgroundProcessor BLOCKED** (session expiry and reload
    silently stop), session-replication lock convoys, JSP-compilation storms.
  - *WebSphere*: **WebContainer saturation** (the WSVR0605W incident, seen before WAS
    says so), **Liberty default-executor blocked saturation** (growth can't help when
    workers are BLOCKED), **OOM-triggered javacore** surfaced as CRITICAL, WAS J2C
    connection-pool waits (`FreePool.createOrWaitForConnection`) in the pool-exhaustion
    detector, SIB messaging-engine waits.
* **Frame meanings** (`frame-meanings.yaml`, override with `--frame-meanings`): every
  thread gets a plain-English "what is this thread doing" line (Oracle JDBC, UCP/Hikari
  borrow, IBM MQ, Kafka poll, Redis, HttpClient/OkHttp, Hibernate, JAX-WS, file I/O,
  crypto, logging) shown in the thread tables, tree annotations, and a per-dump
  "Where is the time going" category breakdown.
* **Work managers**: pools aggregate per WebLogic queue / WebSphere pool / Tomcat exec
  group with busy/idle utilization columns.
* **Pool right-sizing hints** (INFO only, never findings): ≥90% busy with blocked work →
  consider increasing; ≤10% busy at size ≥20 → oversized.

### Rules DSL (`--rules`, `tda rules validate|dry-run`)

Bundled frame-scan detectors and user site packs are the same machinery — one schema:

```yaml
rules:
  - id: mq-reply-wait-storm             # finding id (same id overrides a bundled rule)
    title: "{count} threads waiting on MQ replies"
    severity: warning                    # cap: info|warning|critical
    criticalThreads: 10                  # optional: matches needed to actually go CRITICAL
    recommendation: Check the MQ manager depth and receive timeouts.
    match:
      frames: [com.ibm.mq.jmqi, MQGET]   # any frame contains any needle
      states: [RUNNABLE, WAITING]        # optional
      minThreads: 3                      # per-dump floor
```

A second worked example — a spin detector corroborated by cpu deltas and persistence:

```yaml
rules:
  - id: recon-spin
    title: "{count} reconciler thread(s) burning CPU"
    severity: warning
    recommendation: Profile MatchEngine.scanBucket; suspect the bucket-scan loop.
    match:
      frames: [com.acme.recon.MatchEngine]
      states: [RUNNABLE]
      threadNameRegex: "order-.*"        # optional, full-name regex
      persistDumps: 3                    # same thread across >= 3 consecutive dumps
      cpuDelta: spinning                 # any|zero|spinning (needs cpu= fields or top -H)
```

`tda rules validate <file>` checks the schema; `tda rules dry-run <file> <dumps...>` shows
what would fire without touching the report. Graph-based detectors (deadlock, top blocker,
stuck classification, thread leaks) remain native code — same findings pipeline.

## Fleet and history

* **Cluster mode**: `tda analyze --cluster nodeA=nodeA/*.txt --cluster nodeB=...` (or
  `--cluster-manifest file`) analyzes each node as its own series and adds a cross-node
  section with deterministic, explainable outlier scoring — e.g.
  `node node7 diverges: 34 threads BLOCKED on CacheManager (fleet median: 0)`.
  Add `--cluster-detail` to embed each node's full analysis in the report: a
  "Node drill-down" selector then renders any node's complete single-node view
  (findings, charts, thread browser) inline. Off by default because the report
  grows with node count.
* **Incident memory**: each analysis is stored in an embedded H2 db at `~/.tda/history.db`
  (`--history-db`, `--no-history`); similar past incidents (≥30% Jaccard overlap of
  recurring-stack fingerprints) appear in the report with label/date/shared stacks. CLI:
  `tda history list|search|show`. **The db contains stack frames — treat it with the same
  sensitivity as the dumps themselves.**
* **Release drift**: `tda analyze --label build-2026.07.1 <healthy dumps>` tags a build;
  `tda compare --baseline-label build-2026.07.1 <incident dumps>` shows what changed since
  that build (new recurring stacks, state shifts, pool deltas).

## Ops integration

* **Exit codes** for pipeline gates: `--fail-on critical|warning` → **1** when the
  threshold is met; **0** clean; **2** usage error; **3** parse failure.
* **Webhook** — the ONLY network call this tool can ever make, and only when the flag is
  present: `--webhook <url> [--webhook-format json|slack]` posts the findings summary after
  analysis. Everything else is fully offline, always.
* **Redaction**: `--redact` scrubs hostnames, IPs, and email-like tokens from thread names,
  frames, and lock strings using deterministic pseudonyms (`host-1`, `ip-2`) so
  cross-references still line up; applies to the HTML report, JSON, and webhook payloads.
  Java class names are never touched.
* **Deep links & annotations**: every finding and thread has a stable anchor
  (`#finding-stuck-thread-1`, `#thread-main`); notes can be added per finding/thread and
  "Export annotated report" re-serializes the page with the notes baked in — the artifact
  you attach to an RCA carries its annotations.

## What it detects

Single dump:

* Thread-state distribution, per-pool counts (WebLogic `ExecuteThread` queues,
  `WebContainer : N`, `http-nio-*-exec-N`, `ForkJoinPool`, `pool-N-thread-M`, WildFly,
  XNIO — plus your own patterns via `--pool-pattern`)
* Lock graph over **both** intrinsic monitors and ownable synchronizers; contended locks;
  top blocker (the one thread whose lock release would unblock the most others,
  direct + transitive)
* Deadlocks: the JVM's own report **and** independent wait-for-graph cycle detection
* Identical-stack deduplication (top N recurring stacks with counts)
* WebLogic `[STUCK]` / `[HOGGING]` markers surfaced as findings
* nid ↔ OS-thread mapping, with optional `top -H` join for per-thread CPU

Across a series:

* **Stuck threads**: same stack fingerprint (top N frames, `--fingerprint-depth`) for
  ≥ K consecutive dumps (`--stuck-k`, default 3) while RUNNABLE/BLOCKED, frozen frames as
  evidence. WebLogic's `[ACTIVE]` → `[STUCK]` renames don't break thread matching.
* Per-thread state timelines (swimlane chart for flagged threads)
* Persistent lock holders with the cumulative count of threads they starved
* Per-pool count trends; monotonic growth flags a thread-leak suspect
* **Baseline mode**: `--baseline-save healthy.json` on a known-good series, then
  `--baseline healthy.json` on an incident series diffs state distributions, pool counts,
  and new recurring stacks

Pattern library (each finding = severity + evidence + concrete recommendation):
connection-pool exhaustion (HikariCP / Oracle UCP / WebLogic JDBC / DBCP borrow frames),
synchronized-logging bottleneck, network hangs (`socketRead0` with no timeout), classloader
contention, finalizer backlog, deadlock (always critical), top blocker ranking, thread leaks,
spinning threads (CPU-corroborated busy loops), exception-processing storms.

### False-positive elimination (see `DETECTION_RULES.md`)

A persistent stack fingerprint alone is never a finding. Candidates pass through:

1. an **idle-pattern knowledge base** (`idle-patterns.yaml` in the jar; extend per site with
   `--idle-patterns`) covering accept loops, selector waits, executor queue takes, container
   idle loops - Tomcat's `main` in `StandardServer.await` classifies as
   "idle (acceptor/await loop)", never stuck;
2. a **JVM housekeeping allowlist** (`Reference Handler`, `Finalizer`, GC/JIT workers, ...) -
   exempt unless showing a real anomaly (e.g. Finalizer BLOCKED on an application monitor);
3. **CPU-delta corroboration** using `cpu=` fields (JDK 11+) or `top -H` (JDK 8): zero
   progress in a native frame demotes to INFO; cpu advancing ~ wall clock promotes to a
   spinning-thread finding.

CRITICAL always requires demonstrable impact (deadlock, ≥ `--critical-victims` threads
blocked behind one holder, a spinning thread that blocks others); every finding carries a
confidence level and a "why this is not a false positive" evidence line.

### Extra analysis views

Call-stack tree (all stacks merged, per-node thread counts), last-executed / most-used
method summaries, searchable state-per-dump table for every thread, daemon and GC/JIT
thread tiles, per-thread classification in the thread browser (idle / housekeeping),
`top -H` %CPU and %MEM correlation.

## CLI reference

```
java -jar tda.jar capture --pid <pid> [--count 5] [--interval 10s] [--out dir]
                          [--with-top] [--stdout-log file] [--analyze]
java -jar tda.jar watch   --pid <pid> [--cpu-threshold N] [--thread-count-threshold N]
                          [--poll 5s] [--cooldown 10m] [--exec-after cmd]      (Linux only)
java -jar tda.jar rules   validate <file> | dry-run <file> <dumps...>
java -jar tda.jar history list | search <text> | show <id>
java -jar tda.jar compare --baseline-label <label> <dumps...>

java -jar tda.jar analyze <files...> [options]
  --gc-log <file>            GC/safepoint log overlay + pause reattribution, repeatable
  --jfr-slice <dur>          JFR execution-sample slice (default 1s)
  --rules <file>             site rule pack(s), repeatable
  --frame-meanings <file>    site frame-meaning overrides
  --cluster name=glob        cluster mode, repeatable (also --cluster-manifest)
  --cluster-detail           embed full per-node reports for in-report drill-down
  --label <build>            tag this analysis in history (release drift)
  --no-history / --history-db <path>
  --fail-on critical|warning exit 1 when threshold met (0 clean, 2 usage, 3 parse failure)
  --redact                   deterministic pseudonyms for hosts/IPs/emails
  --webhook <url> [--webhook-format json|slack]   the only (opt-in) network call
  --json <file>              full analysis as JSON (automation-friendly)
  --html <file>              self-contained HTML report (charts inlined; attach to RCA)
  --top <file>               top -H output; joined on nid for per-thread CPU
  --stuck-k <n>              consecutive unchanged dumps before "stuck" (default 3)
  --fingerprint-depth <n>    frames hashed into the fingerprint (default 8)
  --top-stacks <n>           recurring-stack groups reported per dump (default 15)
  --pool-pattern name=regex  extra pool rule, repeatable (group 1 appended to name)
  --idle-patterns <file>     extra idle-pattern YAML (see DETECTION_RULES.md); overrides built-ins by name
  --critical-victims <n>     blocked threads behind one holder before CRITICAL (default 5)
  --baseline-save <file>     save this (healthy) series as a baseline
  --baseline <file>          diff this (incident) series against a saved baseline

java -jar tda.jar serve [--port 8080] [--host 127.0.0.1]
```

`serve` binds to localhost only unless you explicitly change `--host`. The web UI offers the
same analysis plus drag-and-drop upload, `top -H` paste, baseline save/compare, and a
"download standalone report" button. For scripting, `GET /api/analysis` returns the most
recent analysis as JSON (mirrors the CLI's `--json` output).

## Architecture

```
com.tda.core          parsing + analysis, zero web/CLI dependencies (usable as a library)
  ├── model           ThreadDump / ThreadInfo / StackFrame / LockRef / DumpSeries
  ├── parse           DumpSplitter (streaming, log-embedded dumps), HotSpotParser,
  │                   JavacoreParser (IBM J9/OpenJ9), TopHParser
  ├── analysis
  │   ├── single      state distribution, lock graph, deadlocks, stack dedup, pools, CPU
  │   ├── series      thread matching, fingerprints, stuck detection, lock persistence,
  │   │               pool trends, baseline diff
  │   ├── middleware  server detection (WebLogic/WAS/Liberty/Tomcat/WildFly) + the
  │   │               platform health analyzers and the Server-profile panel
  │   └── pattern     the pattern library -> severity-ranked findings
  └── json            dependency-free JSON writer/parser
com.tda.report        JSON + single-file HTML report (ECharts inlined from the jar)
com.tda.web           local web UI on the JDK's built-in HTTP server
com.tda.cli           picocli commands (analyze, serve)
```

Design notes:

* **Streaming parser** — files are read line-by-line, never loaded whole; a 50 MB server log
  parses in seconds and 5,000-thread dumps are covered by tests.
* **Robustness** — truncated dumps, interleaved log lines, and unknown sections are reported
  as parse notes, never crashes.
* Runtime dependencies: picocli. That's it — HTTP is `com.sun.net.httpserver`, JSON is
  in-house, charts are Apache ECharts bundled as a classpath resource (Apache-2.0).
* New dump formats plug in beside `HotSpotParser`; new detectors implement
  `analysis.pattern.Pattern`.

Backlog (not yet supported): Android ART dumps, `hs_err_pid` crash files, core-dump
extraction, AI-assisted chat over findings.

Runtime dependencies grew by exactly one in iteration 3: embedded H2 for the local incident
memory. Everything else is still picocli + the JDK.

## Development

```bash
mvn test        # parser edge cases, every detector, end-to-end report test
mvn package     # runs tests, then shades target/tda.jar
```

Test fixtures under `src/test/resources/fixtures/` are synthetic but format-faithful, in both
JDK 8 and JDK 17 flavors: healthy dumps, a JVM-reported deadlock, HikariCP pool exhaustion,
a five-dump WebLogic incident series (stuck thread, log4j lock convoy, thread leak)
embedded in a server log, and IBM javacores (a traditional-WAS blocked chain on IBM JDK 8,
a Semeru/OpenJ9 `1LKDEADLOCK` deadlock).
