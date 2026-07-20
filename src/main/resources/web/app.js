/* TDA report renderer - shared by the serve-mode web UI and the standalone HTML report.
 * Vanilla JS + Apache ECharts (bundled locally; no network access anywhere). */
"use strict";

const TDA = (() => {

  const STATE_ORDER = ["RUNNABLE", "TIMED_WAITING", "WAITING", "BLOCKED", "NEW", "TERMINATED", "UNKNOWN"];
  const STATE_VAR = {
    RUNNABLE: "--st-runnable", TIMED_WAITING: "--st-timed", WAITING: "--st-waiting",
    BLOCKED: "--st-blocked", NEW: "--st-new", TERMINATED: "--st-gray", UNKNOWN: "--st-gray"
  };

  let meaningsCatalog = []; // frame-meanings for tree annotation (set per render)
  function frameMeaning(frame) {
    for (const m of meaningsCatalog) {
      for (const needle of m.frames) {
        if (frame.includes(needle)) return m;
      }
    }
    return null;
  }

  function slug(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
  }

  // ---- annotations: notes per finding/thread anchor; localStorage in serve mode,
  // ---- baked into the DOM by "Export annotated report" for the RCA artifact path.
  function noteKey(anchor) { return "tda-note-" + anchor; }
  let harvestedNotes = {}; // notes baked into an exported report, recovered before re-render
  function loadNote(anchor) {
    if (harvestedNotes[anchor]) return harvestedNotes[anchor];
    try { return localStorage.getItem(noteKey(anchor)) || ""; } catch (e) { return ""; }
  }
  function attachAnnotation(container, anchor) {
    const btn = el("button", { type: "button", class: "notebtn", title: "Add a note (kept in exports)" }, "✎ note");
    btn.style.cssText = "font-size:11px;padding:1px 8px;margin-left:8px";
    const ta = el("textarea", { class: "tda-note", "data-anchor": anchor,
        placeholder: "RCA note… (included in Export annotated report)" });
    ta.style.cssText = "display:none;margin-top:6px;min-height:48px";
    const saved = ta.getAttribute("data-note") || loadNote(anchor);
    if (saved) { ta.value = saved; ta.style.display = "block"; }
    ta.addEventListener("input", () => {
      try { localStorage.setItem(noteKey(anchor), ta.value); } catch (e) { /* file:// quota */ }
      ta.setAttribute("data-note", ta.value); // survives DOM serialization
    });
    if (saved) ta.setAttribute("data-note", saved);
    btn.addEventListener("click", () => {
      ta.style.display = ta.style.display === "none" ? "block" : "none";
      if (ta.style.display === "block") ta.focus();
    });
    container.appendChild(btn);
    container.appendChild(ta);
  }

  // Re-serializes the current DOM (with data-note attributes) into a new standalone file.
  function exportAnnotatedReport() {
    document.querySelectorAll("textarea.tda-note").forEach(ta => {
      ta.setAttribute("data-note", ta.value);
      ta.textContent = ta.value; // textarea content only serializes via its text node
    });
    const html = "<!DOCTYPE html>\n" + document.documentElement.outerHTML;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    a.download = "tda-report-annotated.html";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ---- drill-down plumbing: charts, findings, and tables navigate into the thread browser
  const drill = { selectDump: null, filterThreads: null, browserEl: null };

  function drillToThreads(opts) { // {dump, state, pool, stackHash, thread}
    if (opts.dump != null && drill.selectDump) drill.selectDump(opts.dump);
    if (drill.filterThreads) drill.filterThreads(opts);
    if (drill.browserEl) drill.browserEl.scrollIntoView({ behavior: "smooth", block: "start" });
    if (opts.thread) setTimeout(() => {
      const row = document.getElementById("thread-" + slug(opts.thread));
      if (row) {
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        const det = row.querySelector("details");
        if (det) det.open = true;
      }
    }, 80);
  }

  /** A clickable thread name that jumps to (and expands) that thread in the browser. */
  function tlink(name, dump) {
    return `<span class="tlink" data-thread="${esc(name)}"` +
        (dump != null ? ` data-dump="${dump}"` : "") + `>${esc(name)}</span>`;
  }

  let charts = [];          // live ECharts instances (disposed on re-render)
  let rebuilders = [];      // functions to rebuild charts on theme change

  const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const stateColor = s => cssVar(STATE_VAR[s] || "--st-gray");
  const catColors = () => [1, 2, 3, 4, 5, 6, 7, 8].map(i => cssVar("--cat-" + i));

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g,
        c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function el(tag, attrs, html) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (html !== undefined) e.innerHTML = html;
    return e;
  }
  function trunc(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }
  function dumpLabel(d) {
    if (d.timestamp) {
      const t = d.timestamp.replace("T", " ").replace(/Z$/, "").split(" ")[1] || d.timestamp;
      return "#" + d.index + " " + t;
    }
    return "#" + d.index;
  }
  function chartTheme() {
    return {
      textStyle: { color: cssVar("--ink-2"), fontFamily: "system-ui, sans-serif" },
      axisLine: { lineStyle: { color: cssVar("--baseline") } },
      splitLine: { lineStyle: { color: cssVar("--grid") } },
      tooltipBg: cssVar("--surface"), ink: cssVar("--ink")
    };
  }
  function baseTooltip() {
    const t = chartTheme();
    return { backgroundColor: t.tooltipBg, borderColor: cssVar("--grid"),
             textStyle: { color: t.ink, fontSize: 12 }, confine: true };
  }
  function makeChart(container, height, build, onClick) {
    const div = el("div", { class: "chart" });
    if (height) div.style.height = height + "px";
    container.appendChild(div);
    const rebuild = () => {
      const c = echarts.init(div, null, { renderer: "canvas" });
      c.setOption(build());
      if (onClick) c.on("click", onClick);
      charts.push(c);
      return c;
    };
    rebuilders.push({ div, rebuild });
    return rebuild();
  }

  // ---------------------------------------------------------------- charts

  // Fractional category-axis position for a wall-clock instant, interpolated between dumps.
  function timeToAxisPos(dumps, tMillis) {
    const times = dumps.map(d => d.timestamp ? Date.parse(d.timestamp) : null);
    if (times.some(x => x == null)) return null;
    if (tMillis <= times[0]) return tMillis < times[0] - 60000 ? null : -0.4;
    for (let i = 1; i < times.length; i++) {
      if (tMillis <= times[i]) {
        return (i - 1) + (tMillis - times[i - 1]) / Math.max(1, times[i] - times[i - 1]);
      }
    }
    return tMillis > times[times.length - 1] + 60000 ? null : times.length - 1 + 0.4;
  }

  // GC/safepoint pause windows as shaded bands (markArea) over a category-axis chart.
  function pauseBands(dumps, gcPauses) {
    if (!gcPauses || !gcPauses.length) return null;
    const data = [];
    for (const p of gcPauses) {
      const s = Date.parse(p.start);
      const a = timeToAxisPos(dumps, s);
      const b = timeToAxisPos(dumps, s + Math.max(p.durationMs, 500)); // min visible width
      if (a == null || b == null) continue;
      data.push([{ xAxis: a, name: `${p.cause} (${Math.round(p.durationMs)}ms)` },
                 { xAxis: Math.max(b, a + 0.03) }]);
      if (data.length >= 80) break;
    }
    if (!data.length) return null;
    return {
      silent: true,
      itemStyle: { color: cssVar("--critical"), opacity: 0.14 },
      label: { show: false },
      data
    };
  }

  function statesChart(container, dumps, gcPauses) {
    makeChart(container, 300, () => {
      const t = chartTheme();
      const cats = dumps.map(dumpLabel);
      const present = STATE_ORDER.filter(s => dumps.some(d => (d.states || {})[s]));
      const bands = pauseBands(dumps, gcPauses);
      const series = present.map(s => ({
        name: s, type: "bar", stack: "states", data: dumps.map(d => (d.states || {})[s] || 0),
        barMaxWidth: 46,
        itemStyle: { color: stateColor(s), borderColor: cssVar("--surface"), borderWidth: 1 }
      }));
      if (bands && series.length) series[0].markArea = bands;
      return {
        tooltip: Object.assign(baseTooltip(), { trigger: "axis", axisPointer: { type: "shadow" } }),
        legend: { top: 0, textStyle: { color: t.textStyle.color, fontSize: 12 } },
        grid: { left: 48, right: 16, top: 34, bottom: 28 },
        xAxis: { type: "category", data: cats, axisLine: t.axisLine,
                 axisLabel: { color: t.textStyle.color } },
        yAxis: { type: "value", splitLine: t.splitLine, axisLabel: { color: t.textStyle.color } },
        series
      };
    }, p => {
      if (p.componentType === "series") {
        drillToThreads({ dump: p.dataIndex, state: p.seriesName });
      }
    });
  }

  function poolTrendChart(container, trends, dumps, gcPauses) {
    if (!trends.length) return;
    const sorted = [...trends].sort((a, b) => Math.max(...b.counts) - Math.max(...a.counts));
    const shown = sorted.slice(0, 8);
    const rest = sorted.slice(8);
    makeChart(container, 300, () => {
      const t = chartTheme();
      const colors = catColors();
      const series = shown.map((p, i) => ({
        name: trunc(p.pool, 40) + (p.leakSuspect ? " ⚠" : ""),
        type: "line", data: p.counts, symbol: "circle", symbolSize: 7,
        lineStyle: { width: 2, color: colors[i] }, itemStyle: { color: colors[i] }
      }));
      if (rest.length) {
        const other = dumps.map((_, i) => rest.reduce((a, p) => a + (p.counts[i] || 0), 0));
        series.push({ name: "Other (" + rest.length + " pools)", type: "line", data: other,
          symbol: "circle", symbolSize: 7,
          lineStyle: { width: 2, type: "dashed", color: cssVar("--muted") },
          itemStyle: { color: cssVar("--muted") } });
      }
      const bands = pauseBands(dumps, gcPauses);
      if (bands && series.length) series[0].markArea = bands;
      return {
        tooltip: Object.assign(baseTooltip(), { trigger: "axis" }),
        legend: { top: 0, type: "scroll", textStyle: { color: t.textStyle.color, fontSize: 11.5 } },
        grid: { left: 48, right: 16, top: 34, bottom: 28 },
        xAxis: { type: "category", data: dumps.map(dumpLabel), axisLine: t.axisLine,
                 axisLabel: { color: t.textStyle.color } },
        yAxis: { type: "value", splitLine: t.splitLine, axisLabel: { color: t.textStyle.color } },
        series
      };
    }, p => {
      if (p.componentType !== "series") return;
      const pool = p.seriesIndex < shown.length ? shown[p.seriesIndex].pool : null;
      drillToThreads({ dump: p.dataIndex, pool });
    });
  }

  function swimlaneChart(container, timelines, dumps) {
    if (!timelines.length) return;
    const rows = timelines.slice(0, 40);
    const h = Math.min(620, 90 + rows.length * 24);
    makeChart(container, h, () => {
      const t = chartTheme();
      const yCats = rows.map(r => trunc(r.name, 46));
      const data = [];
      rows.forEach((r, y) => r.states.forEach((s, x) => {
        if (s) data.push({ value: [x, y, STATE_ORDER.indexOf(s)], state: s, name: r.name, flags: r.flags });
      }));
      return {
        tooltip: Object.assign(baseTooltip(), {
          formatter: p => `<b>${esc(p.data.name)}</b><br>dump ${p.value[0]}: ${p.data.state}` +
                          `<br><span class="sub">${esc((p.data.flags || []).join(", "))}</span>`
        }),
        grid: { left: 8, right: 16, top: 8, bottom: 28, containLabel: true },
        xAxis: { type: "category", data: dumps.map(dumpLabel), axisLine: t.axisLine,
                 axisLabel: { color: t.textStyle.color } },
        yAxis: { type: "category", data: yCats, axisLine: t.axisLine,
                 axisLabel: { color: t.textStyle.color, fontSize: 11 } },
        visualMap: { show: false, type: "piecewise", dimension: 2,
          pieces: STATE_ORDER.map((s, i) => ({ value: i, color: stateColor(s) })) },
        series: [{ type: "heatmap", data,
          itemStyle: { borderColor: cssVar("--surface"), borderWidth: 2, borderRadius: 3 } }]
      };
    }, p => {
      if (p.data && p.data.name) drillToThreads({ dump: p.value[0], thread: p.data.name });
    });
  }

  // Flame/icicle of aggregated RUNNABLE stacks for one dump (root = outermost frame).
  function buildFlameTrie(dump) {
    const root = { name: "all RUNNABLE", value: 0, children: new Map(), threads: [] };
    for (const th of dump.threads) {
      if (th.state !== "RUNNABLE" || !th.stack) continue;
      const frames = dump.stacks[th.stack];
      if (!frames || !frames.length) continue;
      root.value++;
      if (root.threads.length < 20) root.threads.push(th.name);
      let node = root;
      for (const f of [...frames].reverse().slice(0, 30)) {
        let c = node.children.get(f);
        if (!c) { c = { name: f, value: 0, children: new Map(), threads: [] }; node.children.set(f, c); }
        c.value++;
        if (c.threads.length < 20) c.threads.push(th.name);
        node = c;
      }
    }
    return root;
  }

  function flattenFlame(root) {
    const rects = [];
    let maxDepth = 0;
    (function walk(node, depth, start) {
      rects.push([start, node.value, depth, node.name, node]);
      maxDepth = Math.max(maxDepth, depth);
      let s = start;
      for (const c of node.children.values()) { walk(c, depth + 1, s); s += c.value; }
    })(root, 0, 0);
    return { rects, maxDepth };
  }

  // Click a frame to re-root the flame on that subtree; the breadcrumb resets the zoom and
  // the strip below lists the threads passing through the current root as drill-down links.
  function flameChart(container, dump) {
    const fullRoot = buildFlameTrie(dump);
    if (fullRoot.value === 0) {
      container.appendChild(el("p", { class: "sub" }, "No RUNNABLE threads with stacks in this dump."));
      return;
    }
    const crumb = el("div", { class: "crumb" });
    const chartBox = el("div");
    const info = el("div", { class: "sub" });
    container.appendChild(crumb);
    container.appendChild(chartBox);
    container.appendChild(info);
    const zoom = [fullRoot];

    const draw = () => {
      chartBox.innerHTML = "";
      const rootNode = zoom[zoom.length - 1];
      const { rects, maxDepth } = flattenFlame(rootNode);
      const total = rootNode.value;
      const rowH = 18;
      const h = Math.min(520, 60 + (maxDepth + 1) * rowH);
      makeChart(chartBox, h, () => {
        const flame = [1, 2, 3, 4, 5].map(i => cssVar("--flame-" + i));
        return {
          tooltip: Object.assign(baseTooltip(), {
            formatter: p => `<span class="mono">${esc(p.data[3])}</span><br>` +
                            `${p.data[1]} thread(s) · ${(100 * p.data[1] / total).toFixed(1)}% · click to zoom`
          }),
          xAxis: { show: false, max: total },
          yAxis: { show: false, max: Math.max(maxDepth + 1, 1), inverse: true },
          grid: { left: 4, right: 4, top: 6, bottom: 6 },
          series: [{
            type: "custom",
            data: rects,
            renderItem: (params, api) => {
              const item = rects[params.dataIndex];
              const start = api.coord([item[0], item[2]]);
              const end = api.coord([item[0] + item[1], item[2] + 1]);
              const w = end[0] - start[0];
              if (w < 0.6) return null;
              const depth = item[2];
              const name = item[3];
              const shortName = name.replace(/\(.*\)$/, "").split(".").slice(-2).join(".");
              return {
                type: "rect",
                shape: { x: start[0], y: start[1], width: Math.max(w - 1, 0.5), height: rowH - 2, r: 2 },
                style: { fill: flame[depth % flame.length] },
                textContent: w > 60 ? {
                  style: { text: trunc(shortName, Math.floor(w / 6.2)), fontSize: 10.5,
                           fill: depth % flame.length >= 3 ? cssVar("--surface") : cssVar("--ink") }
                } : null,
                textConfig: { position: "insideLeft", inside: true }
              };
            }
          }]
        };
      }, p => {
        const node = rects[p.dataIndex] && rects[p.dataIndex][4];
        if (node && node !== rootNode) { zoom.push(node); draw(); }
      });

      if (zoom.length > 1) {
        crumb.innerHTML = `<span class="tlink" data-zoomreset>⟵ reset zoom</span>` +
            (zoom.length > 2 ? `<span class="tlink" data-zoomup>↑ up one</span>` : "") +
            ` rooted at <span class="mono">${esc(trunc(rootNode.name, 80))}</span> · ${rootNode.value} thread(s)`;
        crumb.querySelector("[data-zoomreset]").addEventListener("click", e => {
          e.stopPropagation(); zoom.length = 1; draw();
        });
        const up = crumb.querySelector("[data-zoomup]");
        if (up) up.addEventListener("click", e => { e.stopPropagation(); zoom.pop(); draw(); });
        info.innerHTML = "threads through this frame: " +
            rootNode.threads.map(n => tlink(n, dump.index)).join(", ") +
            (rootNode.value > rootNode.threads.length ? ", …" : "");
      } else {
        crumb.textContent = "click a frame to zoom into its subtree";
        info.innerHTML = "";
      }
    };
    draw();
  }

  // Collapsible blocker dependency tree; node size follows transitive blocked count.
  function blockerTree(container, dump) {
    const byHolder = new Map();       // holder -> [{waiter, lockClass}]
    const isWaiter = new Set();
    for (const l of dump.contendedLocks || []) {
      if (!l.holder) continue;
      for (const w of l.waiters) {
        if (w === l.holder) continue;
        if (!byHolder.has(l.holder)) byHolder.set(l.holder, []);
        byHolder.get(l.holder).push({ w, lock: l["class"], addr: l.address });
        isWaiter.add(w);
      }
    }
    if (!byHolder.size) {
      container.appendChild(el("p", { class: "sub" }, "No lock contention in this dump."));
      return;
    }
    const seen = new Set();
    function nodeFor(name, lock) {
      const label = { name: trunc(name, 44), realName: name, lock: lock || null, children: [] };
      if (seen.has(name)) { label.name += " (cycle)"; return label; }
      seen.add(name);
      for (const e of byHolder.get(name) || []) {
        label.children.push(nodeFor(e.w, e.lock + " <" + e.addr + ">"));
      }
      seen.delete(name);
      label.value = countLeaves(label);
      return label;
    }
    function countLeaves(n) {
      return n.children.reduce((a, c) => a + 1 + (c.value || countLeaves(c)), 0);
    }
    const roots = [...byHolder.keys()].filter(h => !isWaiter.has(h)).map(h => nodeFor(h, null));
    if (!roots.length) roots.push(nodeFor([...byHolder.keys()][0], null)); // pure cycle (deadlock)
    const root = roots.length === 1 ? roots[0]
        : { name: "contended locks", realName: "", value: 0, children: roots };
    const h = Math.min(560, 160 + 26 * Math.max(4, root.value || 4));
    makeChart(container, h, () => {
      const t = chartTheme();
      return {
        tooltip: Object.assign(baseTooltip(), {
          formatter: p => `<b>${esc(p.data.realName || p.data.name)}</b>` +
              (p.data.lock ? `<br><span class="mono">waiting on ${esc(p.data.lock)}</span>` : "") +
              (p.data.value ? `<br>${p.data.value} thread(s) blocked beneath` : "")
        }),
        series: [{
          type: "tree", data: [root], orient: "LR", roam: true,
          top: 10, bottom: 10, left: 30, right: 240,
          symbolSize: d => 8 + 4 * Math.sqrt(d || 0),
          itemStyle: { color: cssVar("--cat-1"), borderColor: cssVar("--surface") },
          lineStyle: { color: cssVar("--baseline"), width: 1.5 },
          label: { color: t.ink, fontSize: 11.5, position: "right", distance: 6 },
          leaves: { label: { position: "right" } },
          expandAndCollapse: true, initialTreeDepth: 2,
          emphasis: { focus: "descendant" }
        }]
      };
    }, p => {
      if (p.data && p.data.realName) drillToThreads({ dump: dump.index, thread: p.data.realName });
    });
  }

  // ---------------------------------------------------------------- HTML sections

  function stateChip(s) {
    return `<span class="statechip" style="background:${stateColor(s)}"></span>${esc(s)}`;
  }
  function stackDetails(frames, summary) {
    return `<details class="stack"><summary>${esc(summary || "stack")}</summary>` +
           `<pre class="frames">${esc((frames || []).join("\n"))}</pre></details>`;
  }

  function metaSection(root, data) {
    const dumps = data.dumps;
    const last = dumps[dumps.length - 1];
    const sev = { CRITICAL: 0, WARNING: 0, INFO: 0 };
    (data.findings || []).forEach(f => sev[f.severity]++);
    const range = dumps[0].timestamp && last.timestamp
        ? `${dumps[0].timestamp.replace("T", " ").replace("Z", "")} → ${last.timestamp.replace("T", " ").replace("Z", "")}`
        : dumps.map(d => d.source).join(", ");
    const tiles = el("div", { class: "tiles" });
    const tile = (v, l, cls) => tiles.appendChild(
        el("div", { class: "tile" }, `<div class="v ${cls || ""}">${v}</div><div class="l">${l}</div>`));
    tile(dumps.length, "dump" + (dumps.length > 1 ? "s" : ""));
    tile(last.totalThreads, "threads (last dump)");
    tile(`${last.daemonThreads} / ${last.totalThreads - last.daemonThreads}`, "daemon / non-daemon");
    if (last.virtualThreads !== undefined) {
      tile(`${last.platformThreads} / ${last.virtualThreads}`, "platform / virtual");
    }
    if (last.gcThreads !== undefined) {
      tile(`${last.gcThreads} · ${last.jitThreads}`, "GC · JIT threads");
    }
    tile(sev.CRITICAL, "critical findings", sev.CRITICAL ? "leak" : "");
    tile(sev.WARNING, "warnings");
    tile(sev.INFO, "info");
    root.appendChild(tiles);
    const gcNote = dumps.map(d => d.gcJitNote).find(Boolean);
    if (gcNote) root.appendChild(el("p", { class: "sub" }, "⚠ " + esc(gcNote)));
    root.appendChild(el("p", { class: "sub" },
        `${esc(range)} · ${esc(last.banner || "")} · generated ${esc(data.generatedAt)}`));
    const quality = data.qualityNotes || [];
    if (quality.length) {
      root.appendChild(el("div", { class: "card" },
          `<b>Dump quality</b> <span class="badge">${quality.length}</span><div class="sub">` +
          quality.map(n => `<span class="sevtag ${n.level === "WARNING" ? "WARNING" : "INFO"}">` +
              `${esc(n.level)}</span>${esc(n.message)}`).join("<br>") + `</div>`));
    }
    const issues = dumps.flatMap(d => d.issues.map(i => `dump ${d.index}: ${i}`));
    if (issues.length && !quality.length) {
      root.appendChild(el("div", { class: "card" },
          `<b>Parse notes</b> <span class="badge">${issues.length}</span>` +
          `<div class="sub">${issues.map(esc).join("<br>")}</div>`));
    }
  }

  // Detected app server (WebLogic / Tomcat / WebSphere / Liberty / WildFly) + per-dump
  // worker-group health table built from the same math as the platform findings.
  function middlewareSection(root, data) {
    const mw = data.middleware;
    if (!mw || mw.platform === "UNKNOWN") return;
    const h = el("h2", null, "Server profile");
    root.appendChild(h);
    const card = el("div", { class: "card" });
    card.appendChild(el("div", null,
        `<span class="sevtag INFO">${esc(mw.platform)}</span><b>${esc(mw.display)}</b>` +
        `<div class="sub">detected from: ${(mw.evidence || []).map(esc).join(" · ")}</div>`));
    const groups = mw.groups || [];
    if (groups.length) {
      const dumps = data.dumps || [];
      const head = dumps.map(d => `<th class="num">${esc(dumpLabel(d))}</th>`).join("");
      const rows = groups.map(g => {
        const cells = g.perDump.map(c => {
          if (!c) return `<td class="sub num">—</td>`;
          const extras = [];
          if (c.blocked) extras.push(`${c.blocked} blocked`);
          if (c.stuck) extras.push(`${c.stuck} [STUCK]`);
          if (c.standby) extras.push(`${c.standby} standby`);
          return `<td class="num ${c.saturated ? "leak" : ""}">` +
              `${c.busy}/${c.total}${c.saturated ? " ⚠" : ""}` +
              (extras.length ? `<div class="sub">${esc(extras.join(", "))}</div>` : "") + `</td>`;
        }).join("");
        return `<tr><td>${esc(trunc(g.group, 48))}</td>${cells}</tr>`;
      }).join("");
      card.appendChild(el("div", { class: "tablewrap" },
          `<p class="sub">busy/total per dump (busy = not idle-classified); ⚠ marks a fully busy ` +
          `group with no reserve.</p>` +
          `<table><thead><tr><th>Worker group</th>${head}</tr></thead><tbody>${rows}</tbody></table>`));
    }
    root.appendChild(card);
  }

  function findingsSection(root, data) {
    const h = el("h2", null, "Findings");
    const exp = el("button", { type: "button" }, "Export annotated report");
    exp.style.cssText = "float:right;font-size:12px";
    exp.addEventListener("click", exportAnnotatedReport);
    h.appendChild(exp);
    root.appendChild(h);
    const fs = data.findings || [];
    if (!fs.length) {
      root.appendChild(el("p", { class: "sub" }, "No patterns matched. No deadlocks, stuck threads, or known bottlenecks detected."));
      return;
    }
    const anchorCounts = {};
    for (const f of fs) {
      anchorCounts[f.id] = (anchorCounts[f.id] || 0) + 1;
      const anchor = `finding-${slug(f.id)}-${anchorCounts[f.id]}`;
      const ev = f.evidence || {};
      let evHtml = "";
      const evDump = typeof ev.dump === "number" ? ev.dump : null;
      for (const [k, v] of Object.entries(ev)) {
        if (k === "frames") { evHtml += stackDetails(v, "evidence frames"); continue; }
        let val;
        if ((k === "threads" || k === "frozenAcrossDumps") && Array.isArray(v)) {
          val = v.map(x => tlink(String(x), evDump)).join(", ");
        } else if (k === "thread") {
          val = tlink(String(v), evDump);
        } else {
          val = Array.isArray(v) ? v.map(x => esc(String(x))).join(", ") : esc(String(v));
        }
        evHtml += `<div class="sub"><b>${esc(k)}:</b> ${val}</div>`;
      }
      const card = el("div", { class: "card finding " + f.severity, id: anchor },
          `<div><span class="sevtag ${f.severity}">${f.severity}</span><b>${esc(f.title)}</b>` +
          ` <span class="badge">${esc(f.id)}</span> <a class="sub" href="#${anchor}">#</a></div>` +
          `<p>${esc(f.detail)}</p>${evHtml}` +
          `<div class="rec">${esc(f.recommendation)}</div>`);
      attachAnnotation(card, anchor);
      root.appendChild(card);
    }
  }

  function chartsSection(root, data) {
    const dumps = data.dumps;
    root.appendChild(el("h2", null, "Thread states across the series"));
    if ((data.gcPauses || []).length) {
      root.appendChild(el("p", { class: "sub" },
          `Shaded bands mark the ${data.gcPauses.length} GC/safepoint pause window(s) from the supplied GC log.`));
    }
    statesChart(root.appendChild(el("div", { class: "card" })), dumps, data.gcPauses);

    const trends = (data.series && data.series.poolTrends) || [];
    if (trends.length) {
      root.appendChild(el("h2", null, "Thread-pool sizes across the series"));
      poolTrendChart(root.appendChild(el("div", { class: "card" })), trends, dumps, data.gcPauses);
    }
    jfrSections(root, data);
    const timelines = (data.series && data.series.timelines) || [];
    if (timelines.length && dumps.length > 1) {
      root.appendChild(el("h2", null, "Flagged threads — state per dump"));
      root.appendChild(el("p", { class: "sub" },
          "One row per flagged thread (stuck / deadlocked / persistent lock holder / WebLogic-marked). " +
          STATE_ORDER.slice(0, 4).map(stateChip).join("   ")));
      swimlaneChart(root.appendChild(el("div", { class: "card" })), timelines, dumps);
    }
    const allTimelines = (data.series && data.series.allTimelines) || [];
    if (allTimelines.length && dumps.length > 1) {
      root.appendChild(el("h2", null, "All threads — state per dump"));
      allStatesTable(root, allTimelines, dumps);
    }
  }

  // Searchable states-per-dump table covering every matched thread (not just flagged ones).
  function allStatesTable(root, rows, dumps) {
    const card = el("div", { class: "card" });
    root.appendChild(card);
    const controls = el("div", { class: "controls" });
    const q = el("input", { type: "text", placeholder: "filter by thread name…" });
    const st = el("select");
    st.appendChild(el("option", { value: "" }, "any state in any dump"));
    STATE_ORDER.forEach(s => st.appendChild(el("option", { value: s }, s)));
    const count = el("span", { class: "sub" });
    controls.appendChild(q); controls.appendChild(st); controls.appendChild(count);
    card.appendChild(controls);
    const wrap = el("div", { class: "tablewrap" });
    card.appendChild(wrap);
    const renderTable = () => {
      const needle = q.value.toLowerCase();
      const body = [];
      let shown = 0, total = 0;
      for (const r of rows) {
        if (needle && !r.name.toLowerCase().includes(needle)) continue;
        if (st.value && !r.states.includes(st.value)) continue;
        total++;
        if (shown >= 300) continue;
        shown++;
        const cells = r.states.map(s =>
            `<td>${s ? stateChip(s) : '<span class="sub">—</span>'}</td>`).join("");
        body.push(`<tr><td>${esc(trunc(r.name, 70))}</td>${cells}</tr>`);
      }
      count.textContent = shown < total ? `showing ${shown} of ${total}` : `${total} thread(s)`;
      wrap.innerHTML = `<table><thead><tr><th>Thread</th>` +
          dumps.map(d => `<th>${esc(dumpLabel(d))}</th>`).join("") +
          `</tr></thead><tbody>${body.join("")}</tbody></table>`;
    };
    q.addEventListener("input", renderTable);
    st.addEventListener("change", renderTable);
    renderTable();
  }

  // JFR-only sections: lock-contention aggregate and virtual-thread pinning events.
  function jfrSections(root, data) {
    const cont = data.jfrContention || [];
    if (cont.length) {
      root.appendChild(el("h2", null, "Lock contention (JFR events)"));
      const rows = cont.map(c =>
          `<tr><td><span class="badge">${esc(c.kind)}</span></td><td class="mono">${esc(c["class"])}</td>` +
          `<td class="num">${c.count}</td><td class="num">${c.totalMs}ms</td>` +
          `<td class="num">${c.maxMs}ms</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<table><thead><tr><th>Event</th><th>Class</th><th class="num">Count</th>` +
          `<th class="num">Total wait</th><th class="num">Max wait</th></tr></thead>` +
          `<tbody>${rows}</tbody></table>`));
    }
    const pinned = data.jfrPinned || [];
    if (pinned.length) {
      root.appendChild(el("h2", null, "Virtual-thread pinning (JFR events)"));
      const cards = pinned.slice(0, 10).map(p =>
          `<div class="card"><b>${(p.durationMs || 0).toFixed(1)} ms pinned</b>` +
          (p.thread ? ` <span class="sub">${esc(p.thread)}</span>` : "") +
          (p.frames ? stackDetails(p.frames, "pinning stack") : "") + `</div>`).join("");
      root.appendChild(el("div", null, cards));
    }
  }

  // "Similar past incidents" from the local history db (Jaccard overlap of stack sets).
  function similarIncidentsSection(root, data) {
    const sims = data.similarIncidents || [];
    if (!sims.length) return;
    root.appendChild(el("h2", null, "Similar past incidents"));
    root.appendChild(el("p", { class: "sub" },
        "From the local history database - overlap is the Jaccard similarity of recurring-stack fingerprints."));
    for (const s of sims) {
      root.appendChild(el("div", { class: "card" },
          `<b>${esc(s.label || "(unlabeled)")}</b> <span class="badge">#${s.id}</span> ` +
          `<span class="sub">${esc(s.date)}</span> — ` +
          `<b>${Math.round(s.overlap * 100)}%</b> stack overlap` +
          `<div class="sub mono">shared fingerprints: ${s.sharedStacks.map(esc).join(", ")}</div>`));
    }
  }

  // Cluster mode: cross-node comparison + outliers (no per-dump drilldown per node).
  function clusterSection(root, data) {
    const c = data.cluster;
    root.appendChild(el("h2", null, "Cluster overview"));
    const tiles = el("div", { class: "tiles" });
    tiles.appendChild(el("div", { class: "tile" },
        `<div class="v">${c.nodes.length}</div><div class="l">nodes</div>`));
    tiles.appendChild(el("div", { class: "tile" },
        `<div class="v ${c.outliers.length ? "leak" : ""}">${c.outliers.length}</div>` +
        `<div class="l">outlier signals</div>`));
    root.appendChild(tiles);

    if (c.outliers.length) {
      root.appendChild(el("h2", null, "Outliers"));
      for (const o of c.outliers) {
        root.appendChild(el("div", { class: "card finding WARNING" },
            `<span class="sevtag WARNING">OUTLIER</span><b>${esc(o.node)}</b> ` +
            `<span class="badge">${esc(o.kind)}</span><p>${esc(o.explanation)}</p>`));
      }
    } else {
      root.appendChild(el("p", { class: "sub" }, "No outliers — the fleet behaves uniformly."));
    }

    root.appendChild(el("h2", null, "State distribution by node"));
    const states = [...new Set(c.nodes.flatMap(n => Object.keys(n.statePercent)))]
        .sort((a, b) => STATE_ORDER.indexOf(a) - STATE_ORDER.indexOf(b));
    const head = states.map(s => `<th class="num">${stateChip(s)}</th>`).join("");
    const rows = c.nodes.map(n =>
        `<tr><td>${esc(n.node)}</td><td class="num">${n.dumps}</td><td class="num">${n.threads}</td>` +
        states.map(s => `<td class="num">${n.statePercent[s] != null ? n.statePercent[s] + "%" : "—"}</td>`).join("") +
        `<td class="sub">${esc(JSON.stringify(n.findings))}</td></tr>`).join("");
    root.appendChild(el("div", { class: "card tablewrap" },
        `<table><thead><tr><th>Node</th><th class="num">Dumps</th><th class="num">Threads</th>` +
        head + `<th>Findings</th></tr></thead><tbody>${rows}</tbody></table>`));

    root.appendChild(el("h2", null, "Pool utilization by node"));
    const pools = [...new Set(c.nodes.flatMap(n => Object.keys(n.poolBusyPercent)))];
    if (pools.length) {
      const prow = c.nodes.map(n =>
          `<tr><td>${esc(n.node)}</td>` + pools.map(p =>
              `<td class="num">${n.poolBusyPercent[p] != null ? n.poolBusyPercent[p] + "%" : "—"}</td>`).join("") +
          `</tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<table><thead><tr><th>Node</th>` +
          pools.map(p => `<th class="num">${esc(trunc(p, 28))}</th>`).join("") +
          `</tr></thead><tbody>${prow}</tbody></table>`));
    }

    root.appendChild(el("h2", null, "Top recurring stacks by node"));
    for (const n of c.nodes) {
      if (!n.topStacks.length) continue;
      const cards = n.topStacks.map(g =>
          `<div class="card"><b>${g.count} threads</b> <span class="badge">${esc(n.node)}</span>` +
          stackDetails(g.frames, "shared stack") + `</div>`).join("");
      root.appendChild(el("div", null, `<h3>${esc(n.node)}</h3>${cards}`));
    }

    // node drill-down: the full per-node report, embedded with --cluster-detail
    if (c.nodeReports && Object.keys(c.nodeReports).length) {
      root.appendChild(el("h2", null, "Node drill-down"));
      const controls = el("div", { class: "controls" });
      const sel = el("select");
      Object.keys(c.nodeReports).forEach(n => sel.appendChild(el("option", { value: n }, esc(n))));
      controls.appendChild(el("label", null, "Node: "));
      controls.appendChild(sel);
      root.appendChild(controls);
      const box = el("div");
      root.appendChild(box);
      const renderNode = () => {
        box.innerHTML = "";
        renderAnalysis(c.nodeReports[sel.value], box);
      };
      sel.addEventListener("change", renderNode);
      renderNode();
    } else {
      root.appendChild(el("p", { class: "sub" },
          "Run with --cluster-detail to embed each node's full report for drill-down."));
    }
  }

  function seriesSection(root, data) {
    const s = data.series || {};
    const stuck = s.stuckThreads || [];
    if (stuck.length) {
      root.appendChild(el("h2", null, "Long-running / stuck threads"));
      const rows = stuck.map(st =>
          `<tr><td>${tlink(st.name, st.toDump)}</td><td class="num">${st.fromDump}–${st.toDump}</td>` +
          `<td class="num">${st.dumpsUnchanged}</td><td>${st.states.map(stateChip).join(" ")}</td>` +
          `<td><span class="badge">${esc(st.verdict || "")}</span> ` +
          `<span class="sub">${esc(st.confidence || "")}</span></td>` +
          `<td class="num">${st.cpuDeltaMillis != null ? st.cpuDeltaMillis.toFixed(0) + "ms"
              + (st.wallClockSeconds != null ? " / " + st.wallClockSeconds.toFixed(0) + "s" : "") : ""}</td>` +
          `<td>${stackDetails(st.frozenFrames, "frozen stack")}` +
          (st.why ? `<div class="sub">${esc(st.why)}</div>` : "") + `</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<table><thead><tr><th>Thread</th><th class="num">Dumps</th><th class="num">Unchanged</th>` +
          `<th>States</th><th>Verdict</th><th class="num">cpuΔ / wall</th><th>Evidence</th>` +
          `</tr></thead><tbody>${rows}</tbody></table>`));
    }
    const holders = s.persistentLockHolders || [];
    if (holders.length) {
      root.appendChild(el("h2", null, "Persistent lock holders"));
      const rows = holders.map(h => {
        const lastDump = h.dumps[h.dumps.length - 1];
        return `<tr><td>${tlink(h.holder, lastDump)}</td><td class="mono">${esc(h.lockClass)}</td>` +
            `<td class="num">${h.dumps.join(", ")}</td><td class="num">${h.starvedTotal}</td>` +
            `<td class="sub">${h.sampleWaiters.map(n => tlink(n, lastDump)).join(", ")}</td></tr>`;
      }).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<table><thead><tr><th>Holder</th><th>Lock</th><th class="num">Dumps held</th>` +
          `<th class="num">Threads starved</th><th>Waiters (sample)</th></tr></thead><tbody>${rows}</tbody></table>`));
    }
    const bd = s.baselineDiff;
    if (bd) {
      root.appendChild(el("h2", null, "Baseline comparison"));
      const shifts = (bd.stateShifts || []).map(r =>
          `<tr><td>${stateChip(r.state)}</td><td class="num">${r.baselinePercent}%</td>` +
          `<td class="num">${r.incidentPercent}%</td><td class="num ${Math.abs(r.deltaPoints) > 10 ? "leak" : ""}">` +
          `${r.deltaPoints > 0 ? "+" : ""}${r.deltaPoints}pp</td></tr>`).join("");
      const pools = (bd.poolDeltas || []).slice(0, 15).map(r =>
          `<tr><td>${esc(r.pool)}</td><td class="num">${r.baselineAvg}</td>` +
          `<td class="num">${r.incidentAvg}</td><td class="num ${Math.abs(r.delta) >= 5 ? "leak" : ""}">` +
          `${r.delta > 0 ? "+" : ""}${r.delta}</td></tr>`).join("");
      root.appendChild(el("div", { class: "grid2" },
          `<div class="card tablewrap"><h3>State distribution shift</h3><table><thead>` +
          `<tr><th>State</th><th class="num">Baseline</th><th class="num">Incident</th><th class="num">Δ</th></tr>` +
          `</thead><tbody>${shifts}</tbody></table></div>` +
          `<div class="card tablewrap"><h3>Pool average deltas</h3><table><thead>` +
          `<tr><th>Pool</th><th class="num">Baseline</th><th class="num">Incident</th><th class="num">Δ</th></tr>` +
          `</thead><tbody>${pools}</tbody></table></div>`));
      const news = bd.newRecurringStacks || [];
      if (news.length) {
        const cards = news.map(n =>
            `<div class="card"><b>${n.maxCount} threads</b> <span class="sub">in dumps ${n.dumps.join(", ")} — not present in baseline</span>` +
            stackDetails(n.frames, "stack") + `</div>`).join("");
        root.appendChild(el("div", null, `<h3>New recurring stacks (absent from baseline)</h3>${cards}`));
      }
    }
  }

  function dumpSection(root, data) {
    const dumps = data.dumps;
    root.appendChild(el("h2", null, "Per-dump detail"));
    const controls = el("div", { class: "controls" });
    const sel = el("select");
    dumps.forEach(d => sel.appendChild(el("option", { value: d.index },
        esc(dumpLabel(d) + "  (" + d.source + ")"))));
    sel.value = String(dumps.length - 1);
    controls.appendChild(el("label", null, "Dump: "));
    controls.appendChild(sel);
    root.appendChild(controls);
    const body = el("div");
    root.appendChild(body);
    const renderDump = () => { body.innerHTML = ""; renderDumpDetail(body, dumps[+sel.value]); };
    sel.addEventListener("change", renderDump);
    drill.selectDump = i => {
      if (sel.value !== String(i)) {
        sel.value = String(i);
        renderDump();
      }
    };
    renderDump();
  }

  function renderDumpDetail(root, d) {
    // deadlocks
    for (const dl of d.deadlocks || []) {
      root.appendChild(el("div", { class: "card finding CRITICAL" },
          `<span class="sevtag CRITICAL">DEADLOCK</span><b>${dl.threads.length} threads in a cycle</b>` +
          ` <span class="badge">${esc(dl.source)}</span><div class="mono">${dl.threads.map(n => tlink(n, d.index)).join(" → ")}</div>`));
    }
    // flame + blocker tree
    const g2 = el("div", { class: "grid2" });
    root.appendChild(g2);
    const fc = el("div", { class: "card" }, "<h3>RUNNABLE stacks (flame / icicle)</h3>");
    const bc = el("div", { class: "card" }, "<h3>Blocker dependency tree</h3>");
    g2.appendChild(fc); g2.appendChild(bc);
    flameChart(fc, d);
    blockerTree(bc, d);

    callStackTree(root, d);
    methodStats(root, d);

    // carrier mapping (JDK 21+ JSON dumps with virtual threads)
    if ((d.carriers || []).length) {
      const rows = d.carriers.map(c =>
          `<tr><td>${esc(c.carrier)}</td><td class="mono">${esc(c.carrierTid)}</td>` +
          `<td class="num">${c.count}</td>` +
          `<td class="sub">${c.virtualThreads.map(n => tlink(n, d.index)).join(", ")}${c.count > c.virtualThreads.length ? ", …" : ""}</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<h3>Carrier threads → virtual threads</h3><table><thead><tr><th>Carrier</th>` +
          `<th>tid</th><th class="num">Virtual threads</th><th>Names</th></tr></thead>` +
          `<tbody>${rows}</tbody></table>`));
    }

    // pools / work managers with busy-idle utilization; pool names drill into the browser
    if ((d.pools || []).length) {
      const rows = d.pools.map(p => {
        const st = STATE_ORDER.filter(s => p.states[s])
            .map(s => `${stateChip(s)} ${p.states[s]}`).join("   ");
        const busyPct = p.count ? Math.round(100 * (p.busy || 0) / p.count) : 0;
        return `<tr><td><span class="tlink" data-pool="${esc(p.pool)}" data-dump="${d.index}">` +
               `${esc(p.pool)}</span></td><td class="num">${p.count}</td>` +
               `<td class="num">${p.busy != null ? p.busy + ` <span class="sub">(${busyPct}%)</span>` : ""}</td>` +
               `<td class="num">${p.idle != null ? p.idle : ""}</td><td>${st}</td>` +
               `<td class="num ${p.stuck ? "leak" : ""}">${p.stuck || ""}</td></tr>`;
      }).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<h3>Thread pools / work managers</h3><table><thead><tr><th>Pool</th>` +
          `<th class="num">Threads</th><th class="num">Busy</th><th class="num">Idle</th>` +
          `<th>States</th><th class="num">[STUCK]</th></tr></thead><tbody>${rows}</tbody></table>`));
    }
    // "where is the time going": activity-category breakdown
    if (Object.keys(d.categories || {}).length) {
      const rows = Object.entries(d.categories).sort((a, b) => b[1] - a[1]).map(([c, n]) =>
          `<tr><td><span class="badge">${esc(c)}</span></td><td class="num">${n}</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<h3>Where is the time going</h3><p class="sub">Thread counts by recognized activity ` +
          `(frame-meanings knowledge base; unrecognized threads are not shown).</p>` +
          `<table><thead><tr><th>Category</th><th class="num">Threads</th></tr></thead>` +
          `<tbody>${rows}</tbody></table>`));
    }
    // top recurring stacks
    if ((d.topStacks || []).length) {
      const cards = d.topStacks.map(g => {
        const st = Object.entries(g.states).map(([s, n]) => `${stateChip(s)} ${n}`).join("   ");
        return `<div class="card"><b>${g.count} threads</b>  ${st}  ` +
               `<span class="tlink" data-hash="${esc(g.hash)}" data-dump="${d.index}">show all ${g.count} in the browser</span>` +
               `<div class="sub">${g.threads.slice(0, 6).map(n => tlink(n, d.index)).join(", ")}${g.threads.length > 6 ? ", …" : ""}</div>` +
               stackDetails(g.frames, "shared stack") + `</div>`;
      }).join("");
      root.appendChild(el("div", null, `<h3>Top recurring stacks (identical-stack groups)</h3>${cards}`));
    }
    // contended locks
    if ((d.contendedLocks || []).length) {
      const rows = d.contendedLocks.map(l =>
          `<tr><td class="mono">${esc(l.address)}</td><td class="mono">${esc(l["class"])}</td>` +
          `<td>${l.holder ? tlink(l.holder, d.index) : '<span class="sub">(no visible holder)</span>'}</td>` +
          `<td class="num">${l.waiters.length}</td>` +
          `<td class="sub">${l.waiters.slice(0, 5).map(n => tlink(n, d.index)).join(", ")}${l.waiters.length > 5 ? ", …" : ""}</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<h3>Contended locks</h3><table><thead><tr><th>Address</th><th>Class</th><th>Holder</th>` +
          `<th class="num">Waiters</th><th>Waiting threads</th></tr></thead><tbody>${rows}</tbody></table>`));
    }
    // cpu
    if ((d.cpu || []).length) {
      const hasMem = d.cpu.some(c => c.topMemPercent != null);
      const rows = d.cpu.slice(0, 20).map(c =>
          `<tr><td>${esc(c.thread)}</td><td class="mono">${esc(c.nid)} / ${c.nidDec}</td>` +
          `<td>${stateChip(c.state)}</td>` +
          `<td class="num">${c.topPercent != null ? c.topPercent + "%" : ""}</td>` +
          (hasMem ? `<td class="num">${c.topMemPercent != null ? c.topMemPercent + "%" : ""}</td>` : "") +
          `<td class="num">${c.cpuMillis != null ? (c.cpuMillis / 1000).toFixed(1) + "s" : ""}</td>` +
          `<td class="num">${c.elapsedSeconds != null ? c.elapsedSeconds.toFixed(0) + "s" : ""}</td></tr>`).join("");
      root.appendChild(el("div", { class: "card tablewrap" },
          `<h3>CPU attribution <span class="sub">(cpu= header fields and/or top -H join on nid)</span></h3>` +
          `<table><thead><tr><th>Thread</th><th>nid hex/dec</th><th>State</th><th class="num">top %CPU</th>` +
          (hasMem ? `<th class="num">top %MEM</th>` : "") +
          `<th class="num">cpu=</th><th class="num">elapsed=</th></tr></thead><tbody>${rows}</tbody></table>`));
    }
    threadBrowser(root, d);
  }

  // Consolidated expandable call-stack tree over all threads (complement to the flame graph).
  function callStackTree(root, d) {
    const trie = { count: 0, children: new Map() };
    for (const t of d.threads) {
      const frames = t.stack ? d.stacks[t.stack] : null;
      if (!frames || !frames.length) continue;
      trie.count++;
      let node = trie;
      for (const f of [...frames].reverse().slice(0, 40)) {
        let c = node.children.get(f);
        if (!c) { c = { count: 0, children: new Map() }; node.children.set(f, c); }
        c.count++;
        node = c;
      }
    }
    if (!trie.count) return;
    const card = el("div", { class: "card" },
        `<h3>Call stack tree</h3><p class="sub">All ${trie.count} stacks merged from the root ` +
        `frame down; counts show how many threads share each path. Chains with a single child ` +
        `are collapsed into one node.</p>`);
    root.appendChild(card);
    const budget = { nodes: 0 };
    card.appendChild(treeNode(trie, null, budget, true));
    if (budget.nodes >= 3000) {
      card.appendChild(el("p", { class: "sub" }, "…tree truncated at 3000 nodes; use the flame graph or filters for the rest."));
    }
  }

  function treeNode(node, label, budget, open) {
    const box = el("div");
    const entries = [...node.children.entries()].sort((a, b) => b[1].count - a[1].count);
    for (const [frame, child] of entries) {
      if (budget.nodes++ > 3000) break;
      // collapse single-child chains into one summary line
      let chain = [frame];
      let cur = child;
      while (cur.children.size === 1 && [...cur.children.values()][0].count === cur.count) {
        const [f2, c2] = [...cur.children.entries()][0];
        chain.push(f2);
        cur = c2;
      }
      const det = el("details", { class: "stack" });
      if (open && entries.length === 1) det.setAttribute("open", "");
      const label2 = chain.length > 1
          ? `${esc(chain[0].split("(")[0])} <span class="sub">… ${chain.length - 1} more</span>`
          : esc(frame.split("(")[0]);
      const meaning = frameMeaning(chain[chain.length - 1]);
      det.appendChild(el("summary", null,
          `<span class="badge">${cur.count}</span> <span class="mono">${label2}</span>` +
          (meaning ? ` <span class="badge" title="${esc(meaning.activity)}">${esc(meaning.category)}</span>` : "")));
      if (chain.length > 1) {
        det.appendChild(el("pre", { class: "frames" }, esc(chain.join("\n"))));
      }
      if (cur.children.size) det.appendChild(treeNode(cur, frame, budget, false));
      box.appendChild(det);
    }
    return box;
  }

  // fastThread-style "where is the code right now" summaries.
  function methodStats(root, d) {
    const ms = d.methodStats;
    if (!ms || (!ms.lastExecuted.length && !ms.mostUsed.length)) return;
    const tbl = list => list.map(r =>
        `<tr><td class="mono">${esc(r.method)}</td><td class="num">${r.count}</td></tr>`).join("");
    root.appendChild(el("div", { class: "grid2" },
        `<div class="card tablewrap"><h3>Last-executed methods <span class="sub">(top frame)</span></h3>` +
        `<table><thead><tr><th>Method</th><th class="num">Threads</th></tr></thead>` +
        `<tbody>${tbl(ms.lastExecuted)}</tbody></table></div>` +
        `<div class="card tablewrap"><h3>Most-used methods <span class="sub">(any frame)</span></h3>` +
        `<table><thead><tr><th>Method</th><th class="num">Occurrences</th></tr></thead>` +
        `<tbody>${tbl(ms.mostUsed)}</tbody></table></div>`));
  }

  function threadBrowser(root, d) {
    const card = el("div", { class: "card" }, "<h3>All threads</h3>");
    root.appendChild(card);
    const controls = el("div", { class: "controls" });
    const q = el("input", { type: "text",
        placeholder: "filter by name, nid/tid, or class/package/method in the stack…" });
    q.style.minWidth = "320px";
    const st = el("select");
    st.appendChild(el("option", { value: "" }, "any state"));
    STATE_ORDER.forEach(s => st.appendChild(el("option", { value: s }, s)));
    const dm = el("select");
    [["", "daemon + non-daemon"], ["y", "daemon only"], ["n", "non-daemon only"]]
        .forEach(([v, l]) => dm.appendChild(el("option", { value: v }, l)));
    const pr = el("select");
    pr.appendChild(el("option", { value: "" }, "any priority"));
    [...new Set(d.threads.map(t => t.prio).filter(p => p != null))].sort((a, b) => a - b)
        .forEach(p => pr.appendChild(el("option", { value: p }, "prio " + p)));
    const pl = el("select");
    pl.appendChild(el("option", { value: "" }, "any pool"));
    [...new Set(d.threads.map(t => t.pool).filter(Boolean))].sort()
        .forEach(x => pl.appendChild(el("option", { value: x }, trunc(x, 40))));
    controls.appendChild(q); controls.appendChild(st); controls.appendChild(dm);
    controls.appendChild(pr); controls.appendChild(pl);
    let stackHash = null; // programmatic filter from "show all N in the browser" drill-downs
    const chip = el("span");
    controls.appendChild(chip);
    const count = el("span", { class: "sub" });
    controls.appendChild(count);
    card.appendChild(controls);
    const updateChip = () => {
      chip.innerHTML = stackHash
          ? `<span class="filterchip">stack ${esc(stackHash)} <b title="clear">✕</b></span>` : "";
      const x = chip.querySelector("b");
      if (x) x.addEventListener("click", () => { stackHash = null; updateChip(); renderList(); });
    };
    const list = el("div", { class: "tablewrap" });
    card.appendChild(list);
    const renderList = () => {
      const needle = q.value.toLowerCase();
      const rows = [];
      let shown = 0, total = 0;
      for (const t of d.threads) {
        if (st.value && t.state !== st.value) continue;
        if (dm.value === "y" && !t.daemon) continue;
        if (dm.value === "n" && t.daemon) continue;
        if (pr.value !== "" && String(t.prio) !== pr.value) continue;
        if (pl.value !== "" && t.pool !== pl.value) continue;
        if (stackHash && t.stack !== stackHash) continue;
        const frames = t.stack ? d.stacks[t.stack] : [];
        if (needle) {
          const hay = (t.name + " " + (t.nid || "") + " " + (t.nidDec || "") + " "
              + (t.tid || "") + " " + (t["class"] || "")).toLowerCase();
          if (!hay.includes(needle)
              && !(frames || []).some(f => f.toLowerCase().includes(needle))) continue;
        }
        total++;
        if (shown >= 400) continue;
        shown++;
        const anchor = `thread-${slug(t.name)}`;
        rows.push(`<tr id="${anchor}"><td>${esc(t.name)}${t.daemon ? ' <span class="badge">daemon</span>' : ""}` +
            ` <a class="sub" href="#${anchor}">#</a></td>` +
            `<td>${stateChip(t.state)}</td>` +
            `<td class="sub">${esc(t["class"] || "")}${t.activity ? (t["class"] ? " · " : "") +
                esc(t.activity) + ` <span class="badge">${esc(t.category)}</span>` : ""}</td>` +
            `<td class="sub">${esc(t.pool || "")}</td>` +
            `<td class="num">${t.prio != null ? t.prio : ""}</td>` +
            `<td class="mono">${esc(t.nid || "")}</td>` +
            `<td>${frames && frames.length ? stackDetails(frames, frames[0].split("(")[0]) : '<span class="sub">no Java stack</span>'}</td></tr>`);
      }
      count.textContent = shown < total ? `showing ${shown} of ${total}` : `${total} thread(s)`;
      list.innerHTML = `<table><thead><tr><th>Name</th><th>State</th><th>Class</th><th>Pool</th>` +
                       `<th class="num">Prio</th><th>nid</th><th>Stack</th></tr></thead>` +
                       `<tbody>${rows.join("")}</tbody></table>`;
    };
    q.addEventListener("input", renderList);
    [st, dm, pr, pl].forEach(x => x.addEventListener("change", renderList));

    // register as the drill-down target for charts, findings, and tables
    drill.browserEl = card;
    drill.filterThreads = opts => {
      if (opts.state !== undefined) st.value = opts.state || "";
      if (opts.pool !== undefined) {
        pl.value = opts.pool && [...pl.options].some(o => o.value === opts.pool) ? opts.pool : "";
        if (opts.pool && pl.value === "") q.value = opts.pool; // pool absent in this dump
      }
      if (opts.stackHash !== undefined) stackHash = opts.stackHash || null;
      if (opts.thread !== undefined) {
        q.value = opts.thread || "";
        stackHash = null;
        st.value = "";
        pl.value = "";
      } else if (opts.state || opts.pool || opts.stackHash) {
        q.value = "";
      }
      updateChip();
      renderList();
    };
    renderList();
  }

  // ---------------------------------------------------------------- entry point

  /** One delegated listener per root handles every .tlink / stack-hash / pool drill-down. */
  function installDrillListener(root) {
    if (root.dataset.tdaDrill) return;
    root.dataset.tdaDrill = "1";
    root.addEventListener("click", e => {
      const t = e.target.closest("[data-thread], [data-hash], [data-pool]");
      if (!t) return;
      const dump = t.dataset.dump != null ? +t.dataset.dump : undefined;
      if (t.dataset.thread) drillToThreads({ dump, thread: t.dataset.thread });
      else if (t.dataset.hash) drillToThreads({ dump, stackHash: t.dataset.hash });
      else if (t.dataset.pool) drillToThreads({ dump, pool: t.dataset.pool });
    });
  }

  /** The full single-series report body; also reused for cluster node drill-down. */
  function renderAnalysis(data, root) {
    meaningsCatalog = data.meaningsCatalog || [];
    metaSection(root, data);
    middlewareSection(root, data);
    findingsSection(root, data);
    similarIncidentsSection(root, data);
    chartsSection(root, data);
    seriesSection(root, data);
    dumpSection(root, data);
  }

  function render(data, root) {
    charts.forEach(c => c.dispose());
    charts = [];
    rebuilders = [];
    // an exported annotated report re-renders on open: recover its baked-in notes first
    document.querySelectorAll("textarea.tda-note").forEach(ta => {
      const v = ta.getAttribute("data-note") || ta.textContent;
      if (v) harvestedNotes[ta.getAttribute("data-anchor")] = v;
    });
    root.innerHTML = "";
    installDrillListener(root);
    if (data && data.cluster) {
      meaningsCatalog = data.meaningsCatalog || [];
      clusterSection(root, data);
      return;
    }
    if (!data || !data.dumps || !data.dumps.length) {
      root.appendChild(el("p", { class: "err" }, "No thread dumps found in the input."));
      return;
    }
    renderAnalysis(data, root);
    root.appendChild(el("footer", null,
        `tda ${esc((data.tool || {}).version || "")} · fully offline · ` +
        `options: stuckK=${esc(String((data.options || {}).stuckK))}, ` +
        `fingerprintDepth=${esc(String((data.options || {}).fingerprintDepth))}`));
  }

  // theme switches rebuild every chart with fresh CSS-variable colors
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const onTheme = () => {
    charts.forEach(c => c.dispose());
    charts = [];
    rebuilders = rebuilders.filter(r => r.div.isConnected);
    rebuilders.forEach(r => r.rebuild());
  };
  if (media.addEventListener) media.addEventListener("change", onTheme);
  window.addEventListener("resize", () =>
      charts.forEach(c => { if (!c.isDisposed() && c.getDom().isConnected) c.resize(); }));

  return { render };
})();
