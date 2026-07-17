# TDA — Enterprise Thread Dump Analyzer

An offline thread-dump analyzer for middleware engineers (WebLogic, WebSphere, Tomcat,
JBoss/WildFly) diagnosing production incidents. Ingests one dump or an ordered series,
compares dumps against each other, detects long-running/stuck threads, and produces
severity-ranked findings with concrete remediation steps — as an interactive local web UI,
a self-contained HTML report, and JSON for automation.

**Everything runs locally.** One jar, no installer, no database, no telemetry, no CDN, no
network calls of any kind. Dumps contain production data; they never leave the machine.

## Quick start

A prebuilt jar is committed at **`dist/tda.jar`** — copy that one file to any machine with a
Java 17+ runtime and it works, air-gapped included. To build it yourself:

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
snapshot. Five dumps at 10-second intervals is the sweet spot:

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
* Appending all dumps to one file (as above) is fine; passing five separate files is fine
  too. The series is ordered by each dump's own timestamp.

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
contention, finalizer backlog, deadlock (always critical), top blocker ranking, thread leaks.

## CLI reference

```
java -jar tda.jar analyze <files...> [options]
  --json <file>              full analysis as JSON (automation-friendly)
  --html <file>              self-contained HTML report (charts inlined; attach to RCA)
  --top <file>               top -H output; joined on nid for per-thread CPU
  --stuck-k <n>              consecutive unchanged dumps before "stuck" (default 3)
  --fingerprint-depth <n>    frames hashed into the fingerprint (default 8)
  --top-stacks <n>           recurring-stack groups reported per dump (default 15)
  --pool-pattern name=regex  extra pool rule, repeatable (group 1 appended to name)
  --baseline-save <file>     save this (healthy) series as a baseline
  --baseline <file>          diff this (incident) series against a saved baseline

java -jar tda.jar serve [--port 8080] [--host 127.0.0.1]
```

`serve` binds to localhost only unless you explicitly change `--host`. The web UI offers the
same analysis plus drag-and-drop upload, `top -H` paste, baseline save/compare, and a
"download standalone report" button.

## Architecture

```
com.tda.core          parsing + analysis, zero web/CLI dependencies (usable as a library)
  ├── model           ThreadDump / ThreadInfo / StackFrame / LockRef / DumpSeries
  ├── parse           DumpSplitter (streaming, log-embedded dumps), HotSpotParser, TopHParser
  ├── analysis
  │   ├── single      state distribution, lock graph, deadlocks, stack dedup, pools, CPU
  │   ├── series      thread matching, fingerprints, stuck detection, lock persistence,
  │   │               pool trends, baseline diff
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
  `analysis.pattern.Pattern`. (IBM/OpenJ9 javacore support is the planned next format.)

## Development

```bash
mvn test        # parser edge cases, every detector, end-to-end report test
mvn package     # runs tests, then shades target/tda.jar
```

Test fixtures under `src/test/resources/fixtures/` are synthetic but format-faithful, in both
JDK 8 and JDK 17 flavors: healthy dumps, a JVM-reported deadlock, HikariCP pool exhaustion,
and a five-dump WebLogic incident series (stuck thread, log4j lock convoy, thread leak)
embedded in a server log.
