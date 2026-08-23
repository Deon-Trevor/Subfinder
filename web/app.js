/* Subfinder - frontend for the passive subdomain index.
 *
 * The one rule that shapes this file: /v1/search and POST /mcp share a single
 * allowance of 1000 successful reads per IP per UTC day. A browser UI is a new
 * caller on that shared pool, so it never spends a request the user did not ask
 * for. No search on load, no search per keystroke, and a repeat lookup of an
 * apex already read this session is served from memory instead of the API.
 * Filtering, sorting and exporting all work on rows already in hand, so none of
 * them return to the API either.
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
const POLL_MAX_MS = 5 * 60_000;
const FETCH_TIMEOUT_MS = 15_000;
const FILTER_DEBOUNCE_MS = 120;
const SUBMIT_LABEL = "Enumerate";

const el = {
  form: document.getElementById("search-form"),
  input: document.getElementById("apex"),
  submit: document.getElementById("search-submit"),
  topForm: document.getElementById("topsearch-form"),
  topInput: document.getElementById("topsearch"),
  error: document.getElementById("search-error"),
  quota: document.getElementById("quota"),
  quotaText: document.getElementById("quota-text"),
  quotaFill: document.getElementById("quota-fill"),
  register: document.getElementById("register"),
  registerHeading: document.getElementById("register-heading"),
  registerApex: document.getElementById("register-apex"),
  registerCount: document.getElementById("register-count"),
  registerState: document.getElementById("register-state"),
  filterWrap: document.getElementById("filter-wrap"),
  filter: document.getElementById("filter"),
  toolStatus: document.getElementById("tool-status"),
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

/* Older engines miss AbortSignal.timeout, and a hung fetch would otherwise
   stall the poll chain behind it forever. */
function timeoutSignal(ms) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(ms);
  }
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

/* ── theme ───────────────────────────────────────────────────────── */
const stored = (() => {
  try { return localStorage.getItem("subfinder-theme"); } catch { return null; }
})();
if (stored === "light" || stored === "dark") {
  document.documentElement.setAttribute("data-theme", stored);
}

function activeTheme() {
  return document.documentElement.getAttribute("data-theme")
    || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

/* The control offers the theme you would move to, so its label has to name that
   theme rather than the one already on screen. */
function syncThemeToggle() {
  const dark = activeTheme() === "dark";
  el.themeToggle.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  el.themeToggle.setAttribute("aria-pressed", String(dark));
}

el.themeToggle.addEventListener("click", () => {
  const next = activeTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  syncThemeToggle();
  try { localStorage.setItem("subfinder-theme", next); } catch { /* private mode */ }
});

matchMedia("(prefers-color-scheme: dark)").addEventListener("change", syncThemeToggle);
syncThemeToggle();

/* ── the live index counter ──────────────────────────────────────── */
/* /v1/stats is outside the search allowance, so this doubles as the liveness
   signal: an answer here means the index is up, and no separate /health ping
   is needed. Every number shown is a reading the endpoint actually returned.
   The motion between two readings is a tween across real values, never an
   extrapolation, so the counter cannot run ahead of the index. */

let pollTimer = null;
let failures = 0;
let baseline = null;
let shown = 0;
let tween = 0;

function commas(value) {
  return value.toLocaleString("en");
}

/* Count from the last reading to the new one instead of snapping, so a write
   to the index is visible rather than just different on the next glance. A
   token retires the previous frame loop, so two readings landing close together
   cannot leave two loops writing the same node. */
function tweenTo(target) {
  const from = shown;
  if (from === target) return;
  const mine = ++tween;
  const started = performance.now();
  const span = 700;

  const step = (now) => {
    if (mine !== tween) return;
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
    const response = await fetch(`${API_BASE}${STATS_PATH}`, {
      cache: "no-store",
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(String(response.status));
    renderStats(await response.json());
    failures = 0;
  } catch {
    failures += 1;
    statsUnreachable();
  }
}

/* A hidden tab is not watching a counter, so it should not be asking for one.
   A dead index should not be asked every 15 seconds either: each failure backs
   the next attempt off, up to five minutes, and the first success resets it. */
function nextDelay() {
  return failures === 0 ? POLL_MS : Math.min(POLL_MS * 2 ** failures, POLL_MAX_MS);
}

function schedulePoll() {
  stopPolling();
  pollTimer = setTimeout(pollOnce, nextDelay());
}

async function pollOnce() {
  pollTimer = null;
  if (document.hidden) return;
  await readStats();
  if (!document.hidden) schedulePoll();
}

function stopPolling() {
  if (pollTimer === null) return;
  clearTimeout(pollTimer);
  pollTimer = null;
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopPolling();
  } else {
    readStats().then(schedulePoll);
  }
});

readStats().then(schedulePoll);

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

/* Every error path also hides the results section, and reveal() may already
   have put focus on its heading. Sending focus back to the field keeps the
   keyboard somewhere useful instead of dropping it on <body>.

   The message renders under the hero field, so a search run from the bar while
   scrolled down would put the explanation somewhere the reader cannot see.
   In that case the page goes back to the field the message belongs to. */
function showError(headline, detail) {
  el.error.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = headline;
  el.error.append(strong, document.createTextNode(` ${detail}`));
  el.error.hidden = false;

  if (!el.topForm.hidden) {
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.form.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "center" });
  }
  el.input.focus({ preventScroll: true });
}

function clearError() {
  el.error.hidden = true;
  el.error.replaceChildren();
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
  // A single pass rather than Math.min(...years): a busy apex can carry tens of
  // thousands of dated names, and spreading an array that long into a call
  // blows the argument limit and throws.
  const counts = new Map();
  let first = Infinity;
  let last = -Infinity;
  let dated = 0;

  for (const row of rows) {
    const year = yearOf(row.first_seen);
    if (year === null) continue;
    dated += 1;
    if (year < first) first = year;
    if (year > last) last = year;
    counts.set(year, (counts.get(year) || 0) + 1);
  }

  if (dated < 2 || last - first < 1) {
    el.shape.hidden = true;
    return;
  }

  let peak = 0;
  for (const count of counts.values()) if (count > peak) peak = count;

  const span = last - first + 1;
  const tickEvery = span > 12 ? Math.ceil(span / 8) : 1;

  // Give each year a fixed slice of width instead of a share of the page, so a
  // two-year record is a compact pair rather than two bars adrift in 1080px.
  // Both the bars and the axis read this, which is what keeps a tick under its
  // bar at every span.
  el.shape.style.setProperty("--shape-width", `min(100%, ${span * 92}px)`);
  el.shapePeak.textContent = `· peak ${plural(peak, "name")}`;
  el.shapeBars.setAttribute(
    "aria-label",
    `Names first logged per year, ${first} to ${last}. Busiest year holds ${plural(peak, "name")}.`,
  );

  const bars = document.createDocumentFragment();
  const axis = document.createDocumentFragment();

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
    bars.append(cell);

    const tick = document.createElement("span");
    tick.className = "shape-tick";
    tick.textContent = (year - first) % tickEvery === 0 ? `'${String(year).slice(2)}` : "";
    axis.append(tick);
  }

  el.shapeBars.replaceChildren(bars);
  el.shapeAxis.replaceChildren(axis);
  el.shape.hidden = false;
}

function renderLedger(apex, rows) {
  // rows arrive oldest-first with undated names last, so a single pass groups them
  const groups = [];
  for (const row of rows) {
    const year = yearOf(row.first_seen);
    const tail = groups[groups.length - 1];
    if (!tail || tail.year !== year) groups.push({ year, rows: [row] });
    else tail.rows.push(row);
  }

  const suffix = `.${apex}`;
  // One fragment for the whole list: the document is touched once at the end
  // rather than once per year, which matters when a result runs to thousands
  // of rows. CSS then keeps the offscreen years out of layout and paint.
  const fragment = document.createDocumentFragment();

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
    fragment.append(section);
  }

  el.ledger.replaceChildren(fragment);
}

function renderEmpty(apex) {
  const box = document.createElement("div");
  box.className = "state";
  const title = document.createElement("p");
  title.className = "state-title";
  title.textContent = "Nothing on file for this domain.";
  const body = document.createElement("p");
  body.className = "state-body";
  body.textContent = `The index holds no name under ${apex}. That is an answer, not an error, and the domain was not contacted to produce it.`;
  box.append(title, body);
  el.registerState.replaceChildren(box);
}

function renderNoMatches(term) {
  const box = document.createElement("div");
  box.className = "state";
  const title = document.createElement("p");
  title.className = "state-title";
  title.textContent = "No name matches that filter.";
  const body = document.createElement("p");
  body.className = "state-body";
  body.textContent = `Nothing in this result contains "${term}". Clearing the filter brings the whole list back; it never returns to the API.`;
  box.append(title, body);
  el.registerState.replaceChildren(box);
}

function renderLoading() {
  const box = document.createElement("div");
  box.className = "skeleton";
  for (let i = 0; i < 8; i += 1) {
    const row = document.createElement("div");
    row.className = "skeleton-row";
    row.style.width = `${88 - i * 6}%`;
    box.append(row);
  }
  el.registerState.replaceChildren(box);
}

function setCount(total, visible, dated) {
  el.registerCount.replaceChildren();
  if (!total) return;

  el.registerCount.append(document.createTextNode(
    `${plural(total, "name")} · ${dated.toLocaleString("en")} dated`,
  ));
  if (visible === total) return;

  const filtered = document.createElement("span");
  filtered.className = "is-filtered";
  filtered.textContent = ` · ${visible.toLocaleString("en")} shown`;
  el.registerCount.append(filtered);
}

/* Filtering works on rows already in hand, so it costs nothing against the
   allowance no matter how often it runs. */
function visibleRows() {
  const term = el.filter.value.trim().toLowerCase();
  if (!term) return { rows: current.rows, term: "" };
  return { rows: current.rows.filter((row) => row.sub.includes(term)), term };
}

function applyFilter() {
  const { rows, term } = visibleRows();
  const dated = current.rows.reduce((n, row) => n + (row.first_seen ? 1 : 0), 0);
  setCount(current.rows.length, rows.length, dated);

  if (!rows.length) {
    el.ledger.replaceChildren();
    renderNoMatches(term);
    return;
  }

  el.registerState.replaceChildren();
  renderLedger(current.apex, rows);
}

let filterTimer = null;
el.filter.addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, FILTER_DEBOUNCE_MS);
});

function renderRegister(apex, rows) {
  current = { apex, rows };
  syncInputs(apex);
  // A keystroke from the previous result must not re-filter this one.
  clearTimeout(filterTimer);
  el.filter.value = "";
  el.register.hidden = false;
  el.register.removeAttribute("aria-busy");
  el.registerApex.textContent = apex;
  el.registerState.replaceChildren();

  const dated = rows.reduce((n, row) => n + (row.first_seen ? 1 : 0), 0);
  setCount(rows.length, rows.length, dated);

  el.apiLink.href = `${API_BASE}/v1/search?apex=${encodeURIComponent(apex)}&format=json&dates=1`;
  el.filterWrap.hidden = rows.length < 2;

  if (!rows.length) {
    el.ledger.replaceChildren();
    el.shape.hidden = true;
    renderEmpty(apex);
    return;
  }

  renderShape(rows);
  renderLedger(apex, rows);
}

function reveal() {
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Focus first so a keyboard or screen reader lands on the result rather than
  // staying behind in the search field; the scroll then does the visual half.
  el.registerHeading.focus({ preventScroll: true });
  el.register.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
}

/* ── search ──────────────────────────────────────────────────────── */
function normalise(raw) {
  return raw.trim().toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
}

/* A result is worth a URL: it makes the lookup shareable and puts it in the
   back button. Replaying one costs nothing, because the apex is in CACHE by
   then and popstate never reaches the network. */
function syncUrl(apex, push) {
  const url = `${location.pathname}?apex=${encodeURIComponent(apex)}`;
  if (push) history.pushState({ apex }, "", url);
  else history.replaceState({ apex }, "", url);
}

async function search(raw, { push = true } = {}) {
  const apex = normalise(raw);
  if (!apex) return;

  clearError();

  if (CACHE.has(apex)) {
    renderRegister(apex, CACHE.get(apex));
    syncUrl(apex, push && new URLSearchParams(location.search).get("apex") !== apex);
    reveal();
    return;
  }

  el.submit.disabled = true;
  el.submit.textContent = "Reading";
  el.register.hidden = false;
  el.register.setAttribute("aria-busy", "true");
  el.registerApex.textContent = apex;
  el.ledger.replaceChildren();
  el.shape.hidden = true;
  el.filterWrap.hidden = true;
  el.registerCount.replaceChildren();
  renderLoading();
  reveal();

  const url = `${API_BASE}/v1/search?apex=${encodeURIComponent(apex)}&format=json&dates=1`;

  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
    setQuota(response.headers);

    if (response.status === 400) {
      el.register.hidden = true;
      showError("Not a registrable domain.", "Search the domain itself, so example.com rather than mail.example.com.");
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
    syncUrl(apex, push);
    reveal();
  } catch {
    el.register.hidden = true;
    showError("Could not reach the index.", "Check that the API is running on this origin, then try again.");
  } finally {
    el.register.removeAttribute("aria-busy");
    el.submit.disabled = false;
    el.submit.textContent = SUBMIT_LABEL;
  }
}

el.form.addEventListener("submit", (event) => {
  event.preventDefault();
  search(el.input.value);
});

/* ── the search that follows ─────────────────────────────────────── */
/* A result runs long, and the field that produced it is then thousands of rows
   behind you. Rather than a button that scrolls back to the search, the search
   itself comes along: once the hero field passes under the sticky bar, a
   compact copy takes its place there. Reaching it costs no scrolling, and
   nothing new is layered over the page to make room for it. */

el.topForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const value = el.topInput.value;
  el.input.value = value;
  search(value);
});

if ("IntersectionObserver" in window) {
  // The negative top margin is the sticky bar's own height: the hero field is
  // out of reach the moment it slides under the bar, not when it clears the
  // viewport, and the swap should happen then.
  const watcher = new IntersectionObserver(
    ([entry]) => { el.topForm.hidden = entry.isIntersecting; },
    { rootMargin: "-60px 0px 0px 0px" },
  );
  watcher.observe(el.form);
}

/* Both fields show the domain that was actually read, so the normalisation a
   pasted URL goes through is visible rather than silent. */
function syncInputs(apex) {
  el.input.value = apex;
  el.topInput.value = apex;
}

window.addEventListener("popstate", () => {
  const apex = new URLSearchParams(location.search).get("apex");
  if (!apex) {
    el.register.hidden = true;
    syncInputs("");
    return;
  }
  syncInputs(apex);
  search(apex, { push: false });
});

/* "/" is the search key everywhere else a list of hostnames shows up, so it is
   the search key here too - except while something else already has the caret. */
document.addEventListener("keydown", (event) => {
  if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
  const active = document.activeElement;
  if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.isContentEditable)) return;
  event.preventDefault();
  // Whichever field is on screen: the hero one near the top, the bar's below it.
  const field = el.topForm.hidden ? el.input : el.topInput;
  field.focus();
  field.select();
});

/* ── export ──────────────────────────────────────────────────────── */
function payloadFor(mode) {
  const rows = visibleRows().rows;
  return mode === "json"
    ? JSON.stringify(rows, null, 2)
    : rows.map((row) => row.sub).join("\n");
}

function flash(button, message) {
  const label = button.dataset.label ?? button.textContent;
  button.dataset.label = label;
  button.textContent = message;
  button.classList.add("is-done");
  el.toolStatus.textContent = message;
  clearTimeout(Number(button.dataset.timer));
  button.dataset.timer = String(setTimeout(() => {
    button.textContent = button.dataset.label;
    button.classList.remove("is-done");
  }, 1600));
}

for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    if (!current.rows.length) return;
    try {
      await navigator.clipboard.writeText(payloadFor(button.dataset.copy));
      flash(button, "copied");
    } catch {
      flash(button, "blocked");
    }
  });
}

for (const button of document.querySelectorAll("[data-download]")) {
  button.addEventListener("click", () => {
    if (!current.rows.length) return;
    const mode = button.dataset.download;
    const blob = new Blob([payloadFor(mode)], {
      type: mode === "json" ? "application/json" : "text/plain;charset=utf-8",
    });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = `${current.apex}-subdomains.${mode === "json" ? "json" : "txt"}`;
    link.click();
    // Give the download a tick to start before the URL stops resolving.
    setTimeout(() => URL.revokeObjectURL(href), 1000);
    flash(button, "saved");
  });
}

for (const button of document.querySelectorAll("[data-copy-code]")) {
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copyCode);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      flash(button, "Copied");
    } catch {
      flash(button, "Blocked");
    }
  });
}

/* The sample is meant to be pasted, so it names the origin it was served from
   rather than a variable the reader has to define first. */
if (location.protocol === "http:" || location.protocol === "https:") {
  for (const slot of document.querySelectorAll("[data-origin]")) {
    slot.textContent = location.origin;
  }
}

/* Deep link support: /?apex=example.com reads once, on an explicit URL the
   visitor chose to open. A bare visit spends nothing. */
const requested = new URLSearchParams(location.search).get("apex");
if (requested) {
  el.input.value = requested;
  search(requested, { push: false });
}
