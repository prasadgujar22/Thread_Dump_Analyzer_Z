# AGENTS.md

## Cursor Cloud specific instructions

TDA is a self-contained Java 17+ Maven project (a thread dump analyzer). It has no
external services, database server, or network dependencies — everything runs locally
in one JVM. The embedded "incident memory" H2 database is just a file at `~/.tda/history.db`
(pass `--no-history` to avoid touching it during ad-hoc runs).

### Toolchain

- Java 21 is the base JDK (`java -version`). The project builds against release 17 and runs on 17+.
- Maven is provided by the base environment (`mvn -version`). It is not a Maven-wrapper project
  (no `mvnw`), so use the system `mvn`.
- The startup update script runs `mvn dependency:go-offline` to pre-warm the local `~/.m2` cache.
  First `mvn` invocation on a cold cache still downloads plugins; this is normal.

### Build / test / run

Standard commands are documented in `README.md` ("Development" and "Quick start"). In short:

- Test: `mvn test` (JUnit 5; ~119 tests covering parsers, detectors, and an end-to-end report test).
- Build: `mvn package` → shaded `target/tda.jar` (runs tests first; add `-DskipTests` to skip).
- CLI: `java -jar target/tda.jar analyze <dumps...> [--json out.json] [--html report.html] [--no-history]`.
- Web UI: `java -jar target/tda.jar serve --port 8080` (binds `127.0.0.1` only by default).

There is no separate lint step; the build (`mvn package`) is the compile/static gate.

### Non-obvious notes

- Ready-made input fixtures live in `src/test/resources/fixtures/` (WebLogic/Tomcat/WAS dumps,
  javacores, GC logs, JFR-style inputs). `stuck_series_weblogic.log` is a good end-to-end sample
  for `analyze` and for the web UI drag-and-drop.
- The web server keeps only the most recent analysis in memory: `GET /api/analysis` returns 404
  until you POST dumps to `/api/analyze` (or run an analysis via the UI), then returns 200 JSON.
- `serve` is a long-running foreground process — run it in a background terminal/tmux, not inline.
