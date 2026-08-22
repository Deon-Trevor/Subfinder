/* Subfinder - frontend for the certificate transparency index.
 *
 * The one rule that shapes this file: /v1/search and POST /mcp share a single
 * allowance of 1000 successful reads per IP per UTC day. A browser UI is a new
 * caller on that shared pool, so it never spends a request the user did not ask
 * for. No search on load, no search per keystroke, and a repeat lookup of an
 * apex already read this session is served from memory instead of the API.
 *
 * The live counter obeys the same rule from the other direction. It polls
 * /v1/stats, which is outside the allowance, and it polls on a timer, so it
 * must never be pointed at /v1/search: at this interval that would drain a
 * visitor's whole day of reads in about four hours without them searching once.
 */

const API_BASE = "";
const CACHE = new Map();
const STATS_PATH = "/v1/stats";
const POLL_MS = 15_000;
const SUBMIT_LABEL = "Enumerate";

const el = {
  form: document.getElementById("search-form"),
  input: document.getElementById("apex"),
  submit: document.getElementById("search-submit"),
  error: document.getElementById("search-error"),
  quota: document.getElementById("quota"),
  quotaText: document.getElementById("quota-text"),
  quotaFill: document.getElementById("quota-fill"),
  register: document.getElementById("register"),
  registerApex: document.getElementById("register-apex"),
  registerCount: document.getElementById("register-count"),
  registerState: document.getElementById("register-state"),
  ledger: document.getElementById("ledger"),
  shape: document.getElementById("shape"),
  shapeBars: document.getElementById("shape-bars"),
  shapeAxis: document.getElementById("shape-axis"),
  shapePeak: document.getElementById("shape-peak"),
  apiLink: document.getElementById("api-link"),
  themeToggle: document.getElementById("theme-toggle"),
  ticker: document.getElementById("ticker"),
  tickerDot: document.getElementById("ticker-dot"),
  tickerValue: document.getElementById("ticker-value"),
  tickerLabel: document.getElementById("ticker-label"),
  statHostnames: document.getElementById("stat-hostnames"),
  statHostnamesLabel: document.getElementById("stat-hostnames-label"),
  statHostnamesNote: document.getElementById("stat-hostnames-note"),
  statApexes: document.getElementById("stat-apexes"),
  statApexesNote: document.getElementById("stat-apexes-note"),
  statSources: document.getElementById("stat-sources"),
  statSourcesNote: document.getElementById("stat-sources-note"),
  statIngest: document.getElementById("stat-ingest"),
  statIngestNote: document.getElementById("stat-ingest-note"),
};

let current = { apex: "", rows: [] };

/* ── theme ───────────────────────────────────────────────────────── */
const stored = (() => {
  try { return localStorage.getItem("firstseen-theme"); } catch { return null; }
})();
if (stored === "light" || stored === "dark") {
  document.documentElement.setAttribute("data-theme", stored);
}

el.themeToggle.addEventListener("click", () => {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const active = document.documentElement.getAttribute("data-theme") || (dark ? "dark" : "light");
  const next = active === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("firstseen-theme", next); } catch { /* private mode */ }
});

/* ── the live index counter ──────────────────────────────────────── */
/* /v1/stats is outside the search allowance, so this doubles as the liveness
   signal: an answer here means the index is up, and no separate /health ping
   is needed. Every number shown is a reading the endpoint actually returned.
   The motion between two readings is a tween across real values, never an
   extrapolation, so the counter cannot run ahead of the index. */

let poll = null;
let baseline = null;
let shown = 0;

function commas(value) {
  return value.toLocaleString("en");
}

/* Count from the last reading to the new one instead of snapping, so a write
   to the index is visible rather than just different on the next glance. */
function tweenTo(target) {
  const from = shown;
  if (from === target) return;
  const started = performance.now();
  const span = 700;

  const step = (now) => {
    const t = Math.min(1, (now - started) / span);
    const eased = 1 - (1 - t) ** 3;
    shown = Math.round(from + (target - from) * eased);
    el.tickerValue.textContent = commas(shown);
    el.statHostnames.textContent = commas(shown);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function sinceText(timestamp) {
  if (!timestamp) return { text: "never", note: "no ingest run on record" };
  const at = new Date(timestamp);
  if (Number.isNaN(at.getTime())) return { text: String(timestamp), note: "" };

  const stamp = `${at.toISOString().replace("T", " ").slice(0, 19)} UTC`;
  const seconds = Math.max(0, Math.round((Date.now() - at.getTime()) / 1000));
  if (seconds < 45) return { text: "just now", note: stamp };

  const scale = [
    [3600, 60, "minute"],
    [86400, 3600, "hour"],
    [Infinity, 86400, "day"],
  ];
  const [, divisor, unit] = scale.find(([limit]) => seconds < limit);
  const n = Math.max(1, Math.floor(seconds / divisor));
  return { text: `${n} ${unit}${n === 1 ? "" : "s"} ago`, note: stamp };
}

function renderStats(stats) {
  // ct_hostname_count is the count this counter wants: names whose evidence is
  // a CT log rather than a zone file or a crawl. It only wins once it is above
  // zero. An index whose per-source attribution has not been backfilled yet
  // reports 0 there while holding millions of names, and a headline zero reads
  // as a dead service. The label always says which of the two is on screen.
  const ctOnly = Number.isFinite(stats.ct_hostname_count) && stats.ct_hostname_count > 0;
  const hostnames = ctOnly ? stats.ct_hostname_count : stats.hostname_count;
  if (!Number.isFinite(hostnames)) return;

  if (baseline === null) {
    baseline = hostnames;
    shown = hostnames;
    el.tickerValue.textContent = commas(hostnames);
    el.statHostnames.textContent = commas(hostnames);
  } else {
    tweenTo(hostnames);
  }

  const gained = hostnames - baseline;
  el.statHostnamesNote.textContent = gained > 0
    ? `+${commas(gained)} since you opened this page`
    : (ctOnly ? "from certificate transparency" : "across every ingest source");
  el.statHostnamesNote.classList.toggle("is-gain", gained > 0);
  el.statHostnames.classList.toggle("is-rising", gained > 0);
  el.statHostnames.classList.remove("is-down");

  if (Number.isFinite(stats.apex_count)) el.statApexes.textContent = commas(stats.apex_count);
  if (Number.isFinite(stats.hostname_count)) {
    el.statApexesNote.textContent = `${commas(stats.hostname_count)} names across them`;
  }
  const logs = Number.isFinite(stats.ct_log_count) ? stats.ct_log_count : null;
  const feeds = Number.isFinite(stats.source_count) ? stats.source_count : null;
  if (logs !== null || feeds !== null) {
    el.statSources.textContent = commas(logs ?? feeds);
    el.statSourcesNote.textContent = feeds
      ? `${commas(feeds)} ingest ${feeds === 1 ? "source" : "sources"} in all`
      : "no per-source attribution recorded yet";
  }

  const since = sinceText(stats.last_ingest_at);
  el.statIngest.textContent = since.text;
  el.statIngestNote.textContent = since.note;

  el.tickerLabel.textContent = ctOnly ? "from the CT logs" : "names indexed";
  el.statHostnamesLabel.textContent = ctOnly ? "Hostnames from CT logs" : "Hostnames on file";
  el.ticker.hidden = false;
  el.ticker.classList.remove("is-down");
  el.tickerDot.classList.add("is-live");
  el.tickerDot.classList.remove("is-down");
}

function statsUnreachable() {
  el.ticker.hidden = false;
  el.ticker.classList.add("is-down");
  el.tickerDot.classList.remove("is-live");
  el.tickerDot.classList.add("is-down");
  el.tickerValue.textContent = "index unreachable";
  if (baseline !== null) return;
  for (const node of [el.statHostnames, el.statApexes, el.statSources, el.statIngest]) {
    node.textContent = "--";
  }
  el.statHostnames.classList.add("is-down");
  el.statHostnamesNote.textContent = "the stats endpoint did not answer";
}

async function readStats() {
  try {
    const response = await fetch(`${API_BASE}${STATS_PATH}`, { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    renderStats(await response.json());
  } catch {
    statsUnreachable();
  }
}

/* A hidden tab is not watching a counter, so it should not be asking for one. */
function startPolling() {
  if (poll !== null) return;
  poll = setInterval(readStats, POLL_MS);
}

function stopPolling() {
  if (poll === null) return;
  clearInterval(poll);
  poll = null;
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopPolling();
  } else {
    readStats();
    startPolling();
  }
});

readStats();
startPolling();

/* ── helpers ─────────────────────────────────────────────────────── */
function yearOf(firstSeen) {
  if (!firstSeen) return null;
  const year = String(firstSeen).slice(0, 4);
  return /^\d{4}$/.test(year) ? Number(year) : null;
}

function formatDay(firstSeen) {
  if (!firstSeen) return "no date on file";
  const parsed = new Date(firstSeen);
  if (Number.isNaN(parsed.getTime())) return String(firstSeen);
  return parsed.toISOString().slice(0, 10);
}

function plural(n, word) {
  return `${n.toLocaleString("en")} ${word}${n === 1 ? "" : "s"}`;
}

function showError(headline, detail) {
  el.error.innerHTML = "";
  const strong = document.createElement("strong");
  strong.textContent = headline;
  el.error.append(strong, document.createTextNode(` ${detail}`));
  el.error.hidden = false;
}

function clearError() {
  el.error.hidden = true;
  el.error.textContent = "";
}

function setQuota(headers) {
  const limit = Number(headers.get("X-RateLimit-Limit"));
  const remaining = Number(headers.get("X-RateLimit-Remaining"));
  if (!Number.isFinite(limit) || !Number.isFinite(remaining) || limit <= 0) return;

  const ratio = Math.max(0, Math.min(1, remaining / limit));
  el.quota.hidden = false;
  el.quotaText.textContent = `${remaining.toLocaleString("en")} of ${limit.toLocaleString("en")} reads left today`;
  el.quotaFill.style.width = `${ratio * 100}%`;
  el.quotaFill.classList.toggle("is-low", ratio <= 0.2 && remaining > 0);
  el.quotaFill.classList.toggle("is-spent", remaining === 0);
  el.quota.classList.toggle("is-spent", remaining === 0);
}

/* ── rendering ───────────────────────────────────────────────────── */
function renderShape(rows) {
  const years = rows.map((row) => yearOf(row.first_seen)).filter((year) => year !== null);
  if (years.length < 2) {
    el.shape.hidden = true;
    return;
  }

  const first = Math.min(...years);
  const last = Math.max(...years);
  if (last - first < 1) {
    el.shape.hidden = true;
    return;
  }

  const counts = new Map();
  for (const year of years) counts.set(year, (counts.get(year) || 0) + 1);
  const peak = Math.max(...counts.values());

  el.shapeBars.innerHTML = "";
  el.shapeAxis.innerHTML = "";
  const span = last - first + 1;
  const tickEvery = span > 12 ? Math.ceil(span / 8) : 1;

  // Give each year a fixed slice of width instead of a share of the page, so a
  // two-year record is a compact pair rather than two bars adrift in 1080px.
  // Both the bars and the axis read this, which is what keeps a tick under its
  // bar at every span.
  el.shape.style.setProperty("--shape-width", `min(100%, ${span * 92}px)`);
  el.shapePeak.textContent = `· peak ${plural(peak, "name")}`;

  for (let year = first; year <= last; year += 1) {
    const count = counts.get(year) || 0;

    // The bar sits in a full-width cell rather than being one: that keeps it
    // aligned with its axis tick while its own width stays capped, so a
    // three-year span reads as three bars instead of three slabs.
    const cell = document.createElement("div");
    cell.className = "shape-cell";

    const bar = document.createElement("div");
    bar.className = "shape-bar";
    // Heights stay anchored at zero. A flat run of years is a flat run, and
    // the range comes from the plot being tall, not from a cropped baseline.
    bar.style.height = count === 0 ? "0%" : `${Math.max(7, (count / peak) * 100)}%`;
    bar.dataset.empty = String(count === 0);
    bar.title = `${year}: ${plural(count, "name")}`;

    // Every year that ties the ceiling is lit, so a repeated peak reads as a
    // repeated peak rather than as one arbitrarily chosen year.
    if (count === peak) bar.dataset.peak = "true";

    cell.append(bar);
    el.shapeBars.append(cell);

    const tick = document.createElement("span");
    tick.className = "shape-tick";
    tick.textContent = (year - first) % tickEvery === 0 ? `'${String(year).slice(2)}` : "";
    el.shapeAxis.append(tick);
  }

  el.shape.hidden = false;
}

function renderLedger(apex, rows) {
  el.ledger.innerHTML = "";

  // rows arrive oldest-first with undated names last, so a single pass groups them
  const groups = [];
  for (const row of rows) {
    const year = yearOf(row.first_seen);
    const tail = groups[groups.length - 1];
    if (!tail || tail.year !== year) groups.push({ year, rows: [row] });
    else tail.rows.push(row);
  }

  const suffix = `.${apex}`;

  for (const group of groups) {
    const section = document.createElement("section");
    section.className = "ledger-year";

    const gutter = document.createElement("div");
    gutter.className = "ledger-gutter";

    const label = document.createElement("div");
    label.className = "ledger-gutter-year";
    if (group.year === null) {
      label.classList.add("is-undated");
      label.textContent = "Undated";
    } else {
      label.textContent = String(group.year);
    }

    const count = document.createElement("div");
    count.className = "ledger-gutter-count";
    count.textContent = plural(group.rows.length, "name");
    gutter.append(label, count);

    const list = document.createElement("div");
    list.className = "ledger-rows";

    for (const row of group.rows) {
      const line = document.createElement("div");
      line.className = "ledger-row";

      const name = document.createElement("span");
      name.className = "ledger-name";
      if (row.sub === apex) {
        name.textContent = row.sub;
      } else if (row.sub.endsWith(suffix)) {
        // show the label that distinguishes this name, and dim the shared apex
        const labelPart = row.sub.slice(0, -suffix.length);
        const strong = document.createElement("span");
        strong.textContent = labelPart;
        const dim = document.createElement("span");
        dim.className = "apex-part";
        dim.textContent = suffix;
        name.append(strong, dim);
      } else {
        name.textContent = row.sub;
      }

      const date = document.createElement("span");
      date.className = "ledger-date";
      date.textContent = formatDay(row.first_seen);

      line.append(name, date);
      list.append(line);
    }

    section.append(gutter, list);
    el.ledger.append(section);
  }
}

function renderEmpty(apex) {
  el.registerState.innerHTML = "";
  const box = document.createElement("div");
  box.className = "state";
  const title = document.createElement("p");
  title.className = "state-title";
  title.textContent = "Nothing on file for this apex.";
  const body = document.createElement("p");
  body.className = "state-body";
  body.textContent = `The index holds no name under ${apex}. That is an answer, not an error, and the domain was not contacted to produce it.`;
  box.append(title, body);
  el.registerState.append(box);
}

function renderLoading() {
  el.registerState.innerHTML = "";
  const box = document.createElement("div");
  box.className = "skeleton";
  for (let i = 0; i < 8; i += 1) {
    const row = document.createElement("div");
    row.className = "skeleton-row";
    row.style.width = `${88 - i * 6}%`;
    box.append(row);
  }
  el.registerState.append(box);
}

function renderRegister(apex, rows) {
  current = { apex, rows };
  el.register.hidden = false;
  el.registerApex.textContent = apex;
  el.registerState.innerHTML = "";

  const dated = rows.filter((row) => row.first_seen).length;
  el.registerCount.textContent = rows.length
    ? `${plural(rows.length, "name")} · ${dated.toLocaleString("en")} dated`
    : "";

  el.apiLink.href = `${API_BASE}/v1/search?apex=${encodeURIComponent(apex)}&format=json&dates=1`;

  if (!rows.length) {
    el.ledger.innerHTML = "";
    el.shape.hidden = true;
    renderEmpty(apex);
    return;
  }

  renderShape(rows);
  renderLedger(apex, rows);
}

function reveal() {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  el.register.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
}

/* ── search ──────────────────────────────────────────────────────── */
async function search(raw) {
  const apex = raw.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (!apex) return;

  clearError();

  if (CACHE.has(apex)) {
    renderRegister(apex, CACHE.get(apex));
    reveal();
    return;
  }

  el.submit.disabled = true;
  el.submit.textContent = "Reading";
  el.register.hidden = false;
  el.registerApex.textContent = apex;
  el.ledger.innerHTML = "";
  el.shape.hidden = true;
  el.registerCount.textContent = "";
  renderLoading();
  reveal();

  const url = `${API_BASE}/v1/search?apex=${encodeURIComponent(apex)}&format=json&dates=1`;

  try {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    setQuota(response.headers);

    if (response.status === 400) {
      el.register.hidden = true;
      showError("Not an apex.", "Search the registrable domain itself, so example.com rather than mail.example.com.");
      return;
    }

    if (response.status === 429) {
      const retry = Number(response.headers.get("Retry-After"));
      const wait = Number.isFinite(retry) ? `${Math.ceil(retry / 60)} min` : "the UTC day boundary";
      el.register.hidden = true;
      showError("Daily allowance spent.", `This IP has used all 1000 reads. The counter resets in ${wait}.`);
      return;
    }

    if (!response.ok) {
      el.register.hidden = true;
      showError(`Read failed (${response.status}).`, "The index did not answer. Try again in a moment.");
      return;
    }

    const rows = await response.json();
    CACHE.set(apex, rows);
    renderRegister(apex, rows);
    reveal();
  } catch {
    el.register.hidden = true;
    showError("Could not reach the index.", "Check that the API is running on this origin, then try again.");
  } finally {
    el.submit.disabled = false;
    el.submit.textContent = SUBMIT_LABEL;
  }
}

el.form.addEventListener("submit", (event) => {
  event.preventDefault();
  search(el.input.value);
});

/* ── export ──────────────────────────────────────────────────────── */
for (const button of document.querySelectorAll("[data-export]")) {
  button.addEventListener("click", async () => {
    if (!current.rows.length) return;
    const mode = button.dataset.export;
    const payload = mode === "json"
      ? JSON.stringify(current.rows, null, 2)
      : current.rows.map((row) => row.sub).join("\n");

    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(payload);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy blocked";
    }
    setTimeout(() => { button.textContent = original; }, 1400);
  });
}

/* Deep link support: /?apex=example.com reads once, on an explicit URL the
   visitor chose to open. A bare visit spends nothing. */
const requested = new URLSearchParams(location.search).get("apex");
if (requested) {
  el.input.value = requested;
  search(requested);
}
