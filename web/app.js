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
const PAGE_SIZE = 500;
/* How much of the register the page itself shows. Rows arrive oldest first, so
   what sits behind the glass is the head of the record - the names that have
   been on file longest - and the rest is in the shelf. Keeping the page to a
   fixed slice is also what stops a 40,000-name apex from turning the landing
   page into a scroll it takes a minute to get out of. */
const TEASER_ROWS = 18;

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
  enrich: document.getElementById("enrich"),
  enrichLede: document.getElementById("enrich-lede"),
  enrichLanes: document.getElementById("enrich-lanes"),
  enrichActions: document.getElementById("enrich-actions"),
  enrichBlocked: document.getElementById("enrich-blocked"),
  enrichRun: document.getElementById("enrich-run"),
  enrichSubmit: document.getElementById("enrich-submit"),
  enrichNote: document.getElementById("enrich-note"),
  filterWrap: document.getElementById("filter-wrap"),
  filter: document.getElementById("filter"),
  toolStatus: document.getElementById("tool-status"),
  ledger: document.getElementById("ledger"),
  case: document.getElementById("case"),
  caseLip: document.getElementById("case-lip"),
  caseOpen: document.getElementById("case-open"),
  caseMore: document.getElementById("case-more"),
  shelf: document.getElementById("shelf"),
  shelfHeading: document.getElementById("shelf-heading"),
  shelfApex: document.getElementById("shelf-apex"),
  shelfCount: document.getElementById("shelf-count"),
  shelfFilter: document.getElementById("shelf-filter"),
  shelfRail: document.getElementById("shelf-rail"),
  shelfBody: document.getElementById("shelf-body"),
  shelfLedger: document.getElementById("shelf-ledger"),
  shelfState: document.getElementById("shelf-state"),
  shelfClose: document.getElementById("shelf-close"),
  shelfPrev: document.getElementById("shelf-prev"),
  shelfNext: document.getElementById("shelf-next"),
  shelfRange: document.getElementById("shelf-range"),
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

let current = {
  apex: "",
  rows: [],
  total: 0,
  datedTotal: 0,
  cursor: null,
  nextCursor: null,
  start: 0,
  back: [],
};

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

/* Renders into whichever surface is live - the page's case or the shelf - and
   returns how many rows it actually drew, which is what the lip reports as
   still being behind the glass. `limit` cuts the list off after a whole number
   of rows; the year it lands in keeps its true count in the gutter, because
   that year does hold that many names whether or not this pane lists them. */
function renderLedger(apex, rows, target, limit = Infinity) {
  // rows arrive oldest-first with undated names last, so a single pass groups them
  const groups = [];
  let drawn = 0;
  for (const row of rows) {
    if (drawn >= limit) break;
    const year = yearOf(row.first_seen);
    const tail = groups[groups.length - 1];
    if (!tail || tail.year !== year) groups.push({ year, rows: [row] });
    else tail.rows.push(row);
    drawn += 1;
  }

  // Second pass for the totals, so a truncated final year still reports the
  // whole year rather than the slice that fitted.
  const totals = new Map();
  for (const row of rows) {
    const key = yearOf(row.first_seen);
    totals.set(key, (totals.get(key) || 0) + 1);
  }

  const suffix = `.${apex}`;
  // One fragment for the whole list: the document is touched once at the end
  // rather than once per year, which matters when a result runs to thousands
  // of rows. CSS then keeps the offscreen years out of layout and paint.
  const fragment = document.createDocumentFragment();

  for (const group of groups) {
    const section = document.createElement("section");
    section.className = "ledger-year";
    // The rail jumps by this, so every year has to be addressable by name.
    section.dataset.year = group.year === null ? "undated" : String(group.year);
    // What the section stands in at while it is scrolled out of view. See
    // contain-intrinsic-size in the stylesheet.
    section.style.setProperty("--rows", String(group.rows.length));

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
    count.textContent = plural(totals.get(group.year) || group.rows.length, "name");
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

  target.replaceChildren(fragment);
  return drawn;
}

function renderEmpty(apex, target) {
  const box = document.createElement("div");
  box.className = "state";
  const title = document.createElement("p");
  title.className = "state-title";
  title.textContent = "Nothing on file for this domain.";
  const body = document.createElement("p");
  body.className = "state-body";
  body.textContent = `The index holds no name under ${apex}. That is an answer, not an error, and the domain was not contacted to produce it.`;
  box.append(title, body);
  target.replaceChildren(box);
}

function renderNoMatches(term, target) {
  const box = document.createElement("div");
  box.className = "state";
  const title = document.createElement("p");
  title.className = "state-title";
  title.textContent = "No name matches that filter.";
  const body = document.createElement("p");
  body.className = "state-body";
  body.textContent = `Nothing on this page contains "${term}". Clearing the filter brings the page back; it never returns to the API.`;
  box.append(title, body);
  target.replaceChildren(box);
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

function setCount(node, total, visible, dated) {
  node.replaceChildren();
  if (!total) return;

  node.append(document.createTextNode(
    `${plural(total, "name")} · ${dated.toLocaleString("en")} dated`,
  ));
  if (visible === total) return;

  const filtered = document.createElement("span");
  filtered.className = "is-filtered";
  filtered.textContent = ` · ${visible.toLocaleString("en")} shown`;
  node.append(filtered);
}

/* Filtering works on the current page already in hand, so it costs nothing
   against the allowance no matter how often it runs. */
function visibleRows() {
  const term = el.filter.value.trim().toLowerCase();
  if (!term) return { rows: current.rows, term: "" };
  return { rows: current.rows.filter((row) => row.sub.includes(term)), term };
}

/* One draw of both surfaces. The page keeps its slice whether the shelf is up
   or not. The shelf renders only the current bounded API page; large records
   are traversed with the pager rather than duplicated into the document. */
function paint() {
  const { rows, term } = visibleRows();
  const open = el.shelf.open;

  setCount(el.registerCount, current.total, rows.length, current.datedTotal);
  setCount(el.shelfCount, current.total, rows.length, current.datedTotal);
  syncPager();

  // The message goes to the live region of the surface being read. Announcing
  // it in both would say it twice to a screen reader.
  const state = open ? el.shelfState : el.registerState;
  (open ? el.registerState : el.shelfState).replaceChildren();

  if (!rows.length) {
    el.ledger.replaceChildren();
    el.shelfLedger.replaceChildren();
    uncase();
    renderNoMatches(term, state);
    return;
  }

  state.replaceChildren();

  const drawn = renderLedger(current.apex, rows, el.ledger, TEASER_ROWS);
  const behind = Math.max(0, current.total - current.start - drawn);
  el.case.classList.toggle("is-cased", behind > 0);
  el.caseLip.hidden = behind === 0;
  if (behind > 0) el.caseMore.textContent = `+${commas(behind)} more`;

  if (open) {
    renderLedger(current.apex, rows, el.shelfLedger);
    renderRail(rows);
  } else {
    // Page rows stay in memory for back navigation, but not in the hidden DOM.
    el.shelfLedger.replaceChildren();
    el.shelfRail.replaceChildren();
    el.shelfRail.hidden = true;
  }
}

/* Back to a bare list: no frame, no fade, no lip, no rail. What is on screen
   is the whole of what there is, so nothing should suggest more behind it. */
function uncase() {
  el.case.classList.remove("is-cased");
  el.caseLip.hidden = true;
  el.shelfRail.replaceChildren();
  el.shelfRail.hidden = true;
}

/* Both fields carry the same term, so whichever one is on screen is the one
   that filters, and the shelf opens onto the filter the page already had. */
let filterTimer = null;
function bindFilter(input, mirror) {
  input.addEventListener("input", () => {
    mirror.value = input.value;
    clearTimeout(filterTimer);
    filterTimer = setTimeout(paint, FILTER_DEBOUNCE_MS);
  });
}

bindFilter(el.filter, el.shelfFilter);
bindFilter(el.shelfFilter, el.filter);

/* ── the year rail ───────────────────────────────────────────────── */
/* The histogram on the page says how the record is shaped; in the shelf that
   same shape is the way through it. One key per year in the result, sized to
   that year's share of it, and pressing one moves the scroll to that year. */
let railFrame = 0;
let railSettle = null;

function renderRail(rows) {
  const counts = new Map();
  for (const row of rows) {
    const year = yearOf(row.first_seen);
    counts.set(year, (counts.get(year) || 0) + 1);
  }

  // A single year is not a rail; it is a label the ledger already carries.
  if (counts.size < 2) {
    el.shelfRail.replaceChildren();
    el.shelfRail.hidden = true;
    return;
  }

  let peak = 0;
  for (const count of counts.values()) if (count > peak) peak = count;

  const fragment = document.createDocumentFragment();
  for (const [year, count] of counts) {
    const key = year === null ? "undated" : String(year);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "rail-year";
    button.dataset.jump = key;
    button.title = `${year === null ? "Undated" : year}: ${plural(count, "name")}`;

    const track = document.createElement("span");
    track.className = "rail-track";
    const bar = document.createElement("span");
    bar.className = "rail-bar";
    // A floor of 8% so a year holding one name is still a target you can hit.
    bar.style.setProperty("--h", `${Math.max(8, (count / peak) * 100)}%`);
    track.append(bar);

    const label = document.createElement("span");
    label.className = "rail-label";
    label.textContent = year === null ? "n/d" : `'${key.slice(2)}`;

    button.append(track, label);
    fragment.append(button);
  }

  el.shelfRail.replaceChildren(fragment);
  el.shelfRail.hidden = false;
  markYear();
}

/* Lights the key for the year currently at the top of the scroll, so the rail
   reports where you are as well as taking you somewhere. Read from the scroll
   position rather than observed: the sections are content-visibility boxes
   whose measured size only resolves as they are reached, and an intersection
   observer over them loses the year on a jump that skips a decade. Twenty-odd
   sections measured once a frame is cheap, and it is always right. */
function markYear() {
  railFrame = 0;
  const band = el.shelfBody.getBoundingClientRect().top + 8;
  let key = el.shelfLedger.firstElementChild?.dataset.year ?? null;

  // Sections are in document order, so the last one that has passed the band
  // is the one being read.
  for (const section of el.shelfLedger.children) {
    if (section.getBoundingClientRect().top > band) break;
    key = section.dataset.year;
  }

  for (const button of el.shelfRail.children) {
    button.classList.toggle("is-here", button.dataset.jump === key);
  }
}

el.shelfBody.addEventListener("scroll", () => {
  if (!railFrame) railFrame = requestAnimationFrame(markYear);
  // Sections resolve their real heights as they are reached, which can settle
  // after the frame the scroll event was raised in. A second read once things
  // have stopped moving is what keeps the rail from lighting the year the
  // estimate said you were in.
  clearTimeout(railSettle);
  railSettle = setTimeout(markYear, 140);
}, { passive: true });

/* Instant, not smooth. A jump across twenty years of a busy apex is twenty
   thousand pixels, which is a long ride to sit through, and the rows on the
   way are content-visibility sections whose real heights only resolve as they
   are reached - a smooth run retargets under itself and stalls short.
   One write is not enough for the same reason: the first landing is computed
   from estimated heights, so it settles a little off. Reading scrollTop back
   forces the layout that the write invalidated, which resolves the sections
   just passed, and the next pass corrects against their real heights. Three
   or four passes converge; the loop also stops the moment the scroller
   refuses to move, which is how it gives up at either end. */
function jumpTo(section) {
  let stuck = -1;
  for (let pass = 0; pass < 16; pass += 1) {
    const delta = section.getBoundingClientRect().top - el.shelfBody.getBoundingClientRect().top;
    if (Math.abs(delta) < 2) break;

    const before = el.shelfBody.scrollTop;
    el.shelfBody.scrollTop = before + delta;
    const after = el.shelfBody.scrollTop;

    // A write that lands short is not a dead end. Until a section has been
    // rendered once it stands in at its estimated height, so the scroller is
    // shorter than the list really is and the write clamps - but the clamp
    // still renders everything it passed, which grows the scroller and lets
    // the next pass reach further. Only a pass that moves nothing twice
    // running means there is genuinely nothing left to give.
    if (after === before && after === stuck) break;
    stuck = before;
  }
  markYear();
}

el.shelfRail.addEventListener("click", (event) => {
  const button = event.target.closest("[data-jump]");
  if (!button) return;
  const section = el.shelfLedger.querySelector(`[data-year="${button.dataset.jump}"]`);
  if (section) jumpTo(section);
});

function syncPager() {
  const first = current.total ? current.start + 1 : 0;
  const last = current.start + current.rows.length;
  el.shelfRange.textContent = current.total
    ? `${commas(first)}-${commas(last)} of ${commas(current.total)}`
    : "No names on file";
  el.shelfPrev.disabled = current.loading || current.back.length === 0;
  el.shelfNext.disabled = current.loading || !current.nextCursor;
}

function pageUrl(apex, cursor = null) {
  const params = new URLSearchParams({
    apex,
    format: "json",
    dates: "1",
    limit: String(PAGE_SIZE),
  });
  if (cursor) params.set("cursor", cursor);
  return `${API_BASE}/v1/search?${params}`;
}

function integerHeader(headers, name, fallback) {
  const value = Number.parseInt(headers.get(name) ?? "", 10);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

async function readPage(apex, cursor = null) {
  const response = await fetch(pageUrl(apex, cursor), {
    headers: { Accept: "application/json" },
    signal: timeoutSignal(FETCH_TIMEOUT_MS),
  });
  setQuota(response.headers);
  if (!response.ok) {
    const error = new Error(`read failed (${response.status})`);
    error.status = response.status;
    error.retryAfter = response.headers.get("Retry-After");
    throw error;
  }
  const rows = await response.json();
  return {
    rows,
    total: integerHeader(response.headers, "X-Result-Total", rows.length),
    datedTotal: integerHeader(
      response.headers,
      "X-Result-Dated-Total",
      rows.reduce((count, row) => count + (row.first_seen ? 1 : 0), 0),
    ),
    nextCursor: response.headers.get("X-Next-Cursor"),
  };
}

function clearPageFilter() {
  clearTimeout(filterTimer);
  el.filter.value = "";
  el.shelfFilter.value = "";
}

async function nextPage() {
  if (current.loading || !current.nextCursor) return;
  const cursor = current.nextCursor;
  const previous = {
    rows: current.rows,
    cursor: current.cursor,
    nextCursor: current.nextCursor,
    start: current.start,
  };
  current.loading = true;
  syncPager();
  el.shelfState.textContent = "Reading the next page...";
  try {
    const page = await readPage(current.apex, cursor);
    current.back.push(previous);
    current.rows = page.rows;
    current.cursor = cursor;
    current.nextCursor = page.nextCursor;
    current.start = previous.start + previous.rows.length;
    current.total = page.total;
    current.datedTotal = page.datedTotal;
    clearPageFilter();
    renderShape(current.rows);
    paint();
    el.shelfBody.scrollTop = 0;
    el.shelfHeading.focus({ preventScroll: true });
  } catch (error) {
    el.shelfState.textContent = error.status === 429
      ? "The daily allowance is spent; this page was not read."
      : "The next page could not be read. Try again in a moment.";
  } finally {
    current.loading = false;
    syncPager();
  }
}

function previousPage() {
  if (current.loading || !current.back.length) return;
  const previous = current.back.pop();
  current.rows = previous.rows;
  current.cursor = previous.cursor;
  current.nextCursor = previous.nextCursor;
  current.start = previous.start;
  clearPageFilter();
  renderShape(current.rows);
  paint();
  el.shelfBody.scrollTop = 0;
  el.shelfHeading.focus({ preventScroll: true });
}

el.shelfNext.addEventListener("click", nextPage);
el.shelfPrev.addEventListener("click", previousPage);

/* ── opening and closing the shelf ───────────────────────────────── */
/* showModal is what earns the shelf its behaviour: the page behind it goes
   inert, Escape closes it, focus cannot tab out the back, and ::backdrop is a
   real layer rather than a div pretending to be one. */
function openShelf() {
  if (!current.rows.length || el.shelf.open) return;
  el.shelfApex.textContent = current.apex;
  el.shelf.showModal();
  paint();
  el.shelfBody.scrollTop = 0;
  // The heading, not the filter: autofocusing a text field would throw up the
  // keyboard on a phone and cover the record the reader just asked to see.
  el.shelfHeading.focus({ preventScroll: true });
}

/* Every way out of the shelf lands here: the close button, a click on the
   backdrop, and Escape - which the dialog handles itself and reports through
   its close event. Dropping the page rows from the dialog is the point. */
function closeShelf() {
  // Already put away: nothing to close, no rows to drop, no focus to move.
  if (!el.shelf.open && !el.shelfLedger.firstChild) return;
  if (el.shelf.open) el.shelf.close();

  cancelAnimationFrame(railFrame);
  clearTimeout(railSettle);
  railFrame = 0;
  paint();

  // Back to the control that opened it. If a filter has since shrunk the
  // result below the glass there is no lip to return to, so the heading takes
  // it rather than dropping focus on <body>.
  const home = el.caseLip.hidden ? el.registerHeading : el.caseOpen;
  home.focus({ preventScroll: true });
}

el.caseOpen.addEventListener("click", openShelf);
el.shelfClose.addEventListener("click", closeShelf);
el.shelf.addEventListener("close", closeShelf);

/* Clicking off the shelf puts it away. The panel is the dialog's only child,
   so a click landing on the dialog landed outside the panel - but the press
   has to have started there too, or dragging a selection out of the list and
   releasing on the backdrop would close it mid-copy. */
let pressedOff = false;
el.shelf.addEventListener("pointerdown", (event) => {
  pressedOff = event.target === el.shelf;
});

el.shelf.addEventListener("click", (event) => {
  if (pressedOff && event.target === el.shelf) closeShelf();
  pressedOff = false;
});

function renderRegister(page) {
  current = page;
  syncInputs(current.apex);
  // A keystroke from the previous result must not re-filter this one.
  clearTimeout(filterTimer);
  el.filter.value = "";
  el.shelfFilter.value = "";
  el.register.hidden = false;
  el.register.removeAttribute("aria-busy");
  el.registerApex.textContent = current.apex;
  el.shelfApex.textContent = current.apex;
  el.registerState.replaceChildren();
  el.shelfState.replaceChildren();

  el.apiLink.href = `${API_BASE}/v1/search?apex=${encodeURIComponent(current.apex)}&format=json&dates=1`;
  el.filterWrap.hidden = current.total < 2;

  if (!current.rows.length) {
    setCount(el.registerCount, 0, 0, 0);
    setCount(el.shelfCount, 0, 0, 0);
    el.ledger.replaceChildren();
    el.shelfLedger.replaceChildren();
    uncase();
    el.shape.hidden = true;
    syncPager();
    renderEmpty(current.apex, el.registerState);
    syncEnrichment();
    return;
  }

  renderShape(current.rows);
  paint();
  syncEnrichment();
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
  // A run is only worth watching while its apex is the one on screen. Reading
  // the same apex again - which is how a finished run replaces its own empty
  // result - keeps it.
  stopEnrichment(apex);

  if (CACHE.has(apex)) {
    renderRegister(CACHE.get(apex));
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
  el.shelfLedger.replaceChildren();
  uncase();
  el.shape.hidden = true;
  el.filterWrap.hidden = true;
  el.registerCount.replaceChildren();
  renderLoading();
  reveal();

  try {
    const page = await readPage(apex);
    const result = {
      apex,
      ...page,
      cursor: null,
      start: 0,
      back: [],
      loading: false,
    };
    CACHE.set(apex, result);
    renderRegister(result);
    syncUrl(apex, push);
    reveal();
  } catch (error) {
    el.register.hidden = true;
    if (error.status === 400) {
      showError("Not a registrable domain.", "Search the domain itself, so example.com rather than mail.example.com.");
    } else if (error.status === 429) {
      const retry = Number(error.retryAfter);
      const wait = Number.isFinite(retry) ? `${Math.ceil(retry / 60)} min` : "the UTC day boundary";
      showError("Daily allowance spent.", `This IP has used all 1000 reads. The counter resets in ${wait}.`);
    } else if (error.status) {
      showError(`Read failed (${error.status}).`, "The index did not answer. Try again in a moment.");
    } else {
      showError("Could not reach the index.", "Check that the API is running on this origin, then try again.");
    }
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
  // A back step that changes the result must not leave the shelf up over it,
  // holding the rows of the domain you just left.
  closeShelf();
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
  // With the shelf up, "/" belongs to the field inside it: the search fields on
  // the page are inert and focusing one would do nothing visible.
  if (el.shelf.open) {
    el.shelfFilter.focus();
    el.shelfFilter.select();
    return;
  }
  // Whichever field is on screen: the hero one near the top, the bar's below it.
  const field = el.topForm.hidden ? el.input : el.topInput;
  field.focus();
  field.select();
});


/* ── enrichment: an empty answer that need not stay empty ────────── */
/* An apex with nothing on file is a real answer, not an error - but the
   records sometimes exist and have simply not been read in yet. The API
   reports which of two are already on hand: an approved zone artifact sitting
   in the managed directory, and URLScan history for scans that have already
   been taken.

   Neither one reaches the domain, and the copy below never suggests
   otherwise. Subfinder does not download a zone it does not have, so the offer
   is only ever to import a file already on that disk; and "URLScan" here is a
   search of scans other people already ran, never a new one. That is what lets
   this offer sit on a page whose whole claim is that a lookup sends the target
   nothing. */

const ENRICH_POLL_FLOOR_S = 1;
const ENRICH_POLL_CEILING_S = 30;
/* A run that has not reached a terminal state in this long has stopped being
   something to watch. Polling gives up and hands the reader a control instead,
   rather than holding a timer open for the rest of the visit. */
const ENRICH_WATCH_MS = 5 * 60_000;

const ENRICH_ORDER = ["local_zone", "urlscan"];
const ENRICH_NAMES = { local_zone: "Zone file", urlscan: "URLScan history" };

/* What each lane says when the job reports it unavailable. The job document
   carries lane states but no prose; only the options document explains itself,
   and by the time a lane reports in, that document may be a minute stale. */
const ENRICH_ABSENT = {
  local_zone: "No approved zone artifact is on disk for this zone.",
  urlscan: "Passive URLScan reading is not configured on this deployment.",
};

let enrich = null;

function bytesText(value) {
  if (!Number.isFinite(value) || value <= 0) return "";
  const units = ["bytes", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${unit === 0 ? size : size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

/* One key per apex and action selection. A retry after a dropped connection
   then joins the job it already started instead of paying for a second one,
   and a different selection is a different request - which is exactly what the
   API refuses a reused key for. It is held in sessionStorage so that a reload
   mid-run rejoins the run rather than orphaning it. */
function idempotencyKey(apex, actions) {
  const slot = `subfinder-enrich:${apex}:${actions.join(",")}`;
  try {
    const held = sessionStorage.getItem(slot);
    if (held) return held;
  } catch { /* private mode */ }

  const minted = typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID()
    : `${apex}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  try { sessionStorage.setItem(slot, minted); } catch { /* private mode */ }
  return minted;
}

function forgetKey(apex, actions) {
  try { sessionStorage.removeItem(`subfinder-enrich:${apex}:${actions.join(",")}`); } catch { /* private mode */ }
}

function stopEnrichment(keepFor = null) {
  if (!enrich) return;
  if (keepFor !== null && enrich.apex === keepFor) return;
  clearTimeout(enrich.timer);
  enrich = null;
  el.enrich.hidden = true;
  el.enrichLanes.hidden = true;
  el.enrichLanes.replaceChildren();
  el.enrichActions.replaceChildren();
  el.enrichRun.hidden = true;
  el.enrichBlocked.hidden = true;
  setEnrichNote("");
}

function setEnrichNote(text, bad = false) {
  el.enrichNote.textContent = text;
  el.enrichNote.classList.toggle("is-bad", bad);
}

/* What the server actually asked for, as seconds. Reported to the reader
   unchanged: a spent daily allowance resets hours from now, and rounding that
   into a polling interval would quote a wait that is not the real one. */
function retryAfter(headers, fallback) {
  const asked = Number.parseInt(headers.get("Retry-After") ?? "", 10);
  return Number.isFinite(asked) && asked >= 0 ? asked : fallback;
}

/* The same header as a polling interval, which does need clamping: missing,
   junk, or very large must not stall the watch or turn it into a hammer. */
function pollDelay(headers, fallback) {
  return Math.min(
    ENRICH_POLL_CEILING_S,
    Math.max(ENRICH_POLL_FLOOR_S, retryAfter(headers, fallback)),
  );
}

function sentence(text) {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

async function detailOf(response, fallback) {
  try {
    const body = await response.json();
    const detail = body && body.detail;
    return typeof detail === "string" && detail ? detail : fallback;
  } catch {
    return fallback;
  }
}

async function readEnrichmentOptions(apex) {
  const response = await fetch(
    `${API_BASE}/v1/enrichment-options?apex=${encodeURIComponent(apex)}`,
    { headers: { Accept: "application/json" }, signal: timeoutSignal(FETCH_TIMEOUT_MS) },
  );
  if (!response.ok) {
    const error = new Error(`options failed (${response.status})`);
    error.status = response.status;
    error.retryAfter = retryAfter(response.headers, 5);
    throw error;
  }
  return response.json();
}

/* A finished run keeps the panel it wrote. Re-reading the record is what ends
   the run, and clearing the report in the same breath would leave no account
   of what the run actually did. */
function enrichmentFor(apex) {
  if (enrich && enrich.apex === apex && enrich.job && enrich.job.terminal) {
    el.enrich.hidden = false;
    return;
  }
  openEnrichment(apex);
}

async function openEnrichment(apex) {
  stopEnrichment();
  enrich = {
    apex,
    options: null,
    selected: new Set(),
    job: null,
    jobUrl: null,
    timer: null,
    until: 0,
    busy: false,
    // Actions this panel has already run. `actionable` says the capability is
    // published, not that there is anything left to ask for, so URLScan would
    // otherwise be offered again forever - directly under a lane that just
    // said there is nothing more to do there.
    ran: new Set(),
    // Actions whose lane came back failed, and so are worth asking for again.
    retry: new Set(),
    lastActions: [],
    laneSignature: "",
  };

  let options;
  try {
    options = await readEnrichmentOptions(apex);
  } catch (error) {
    // The empty answer is correct with or without this panel, so a route that
    // is missing or briefly down gets no alarm raised over it. Only a stated
    // overload earns a line, because that one is worth coming back from.
    if (error.status === 503 && enrich && enrich.apex === apex) {
      el.enrichLede.textContent =
        `Whether anything is on hand for ${apex} cannot be read right now.`;
      el.enrichActions.replaceChildren();
      el.enrichBlocked.hidden = true;
      el.enrichRun.hidden = false;
      el.enrichSubmit.hidden = true;
      setEnrichNote(`Try again in about ${plural(error.retryAfter, "second")}.`);
      el.enrich.hidden = false;
    }
    return;
  }

  // A newer search overtook this one while the options were in flight.
  if (!enrich || enrich.apex !== apex) return;
  enrich.options = options;
  renderOffer();
}

function actionRow(name, action, zone) {
  const row = document.createElement("label");
  row.className = "enrich-action";

  const box = document.createElement("input");
  box.type = "checkbox";
  box.className = "enrich-check";
  box.checked = true;
  box.dataset.action = name;
  box.addEventListener("change", () => {
    if (box.checked) enrich.selected.add(name);
    else enrich.selected.delete(name);
    syncEnrichSubmit();
  });

  const title = document.createElement("span");
  title.className = "enrich-action-title";
  const note = document.createElement("span");
  note.className = "enrich-action-note";

  if (name === "local_zone") {
    title.textContent = `Import the ${zone} zone file`;
    const size = bytesText(Number(action.artifact_bytes));
    note.textContent =
      `The approved artifact is already on this disk${size ? ` (${size})` : ""}`
      + " and is read from there. Nothing is fetched to produce it.";
  } else {
    title.textContent = "Read the URLScan history already on file";
    note.textContent =
      "A passive search of scans that have already been run by others."
      + " No scan is submitted, and the domain is not contacted.";
  }

  row.append(box, title, note);
  return row;
}

function renderOffer() {
  const { apex, options } = enrich;
  const actions = (options && options.actions) || {};
  const zone = options.zone || "zone";

  // Only actionable actions are ever offered. The rest are stated below,
  // because why the index is empty is part of the answer to an empty search.
  const open = ENRICH_ORDER.filter(
    (name) => actions[name] && actions[name].actionable && !enrich.ran.has(name),
  );
  const shut = ENRICH_ORDER.filter(
    (name) => actions[name] && !actions[name].actionable && !enrich.ran.has(name),
  );

  enrich.selected = new Set(open);
  el.enrichActions.replaceChildren(
    ...open.map((name) => actionRow(name, actions[name], zone)),
  );

  el.enrichBlocked.replaceChildren();
  for (const name of shut) {
    if (el.enrichBlocked.firstChild) el.enrichBlocked.append(document.createElement("br"));
    // reason is the API's own words for why this one cannot run
    el.enrichBlocked.append(`${ENRICH_NAMES[name]} - ${actions[name].reason}`);
  }
  el.enrichBlocked.hidden = shut.length === 0;

  const ran = Boolean(enrich.job && enrich.job.terminal);
  if (!ran && open.length) {
    el.enrichLede.textContent =
      `Nothing was read from ${apex} to produce this empty answer, and nothing`
      + " below would be either. These records already exist elsewhere; they"
      + " have just not been read into the index yet.";
  } else if (!ran) {
    el.enrichLede.textContent = `Nothing is on hand to read in for ${apex} right now.`;
  } else if (open.some((name) => enrich.retry.has(name))) {
    el.enrichLede.textContent =
      "Nothing was read in from that one, so it is worth another go."
      + " Asking again starts a fresh attempt rather than replaying the last.";
  } else if (open.length) {
    el.enrichLede.textContent =
      `One more record is on hand for ${apex}, and reads the same way: without contacting it.`;
  } else {
    el.enrichLede.textContent = `Nothing further is on hand for ${apex}.`;
  }

  el.enrichRun.hidden = open.length === 0;
  el.enrichSubmit.hidden = false;
  el.enrich.hidden = false;
  syncEnrichSubmit();
}

function syncEnrichSubmit() {
  const count = enrich ? enrich.selected.size : 0;
  el.enrichSubmit.disabled = !enrich || enrich.busy || count === 0;
  if (enrich && enrich.busy) {
    el.enrichSubmit.textContent = "Reading";
    return;
  }
  el.enrichSubmit.textContent = count > 1 ? "Read them in" : "Read it in";
}

/* ── lanes ───────────────────────────────────────────────────────── */
/* Each lane reports for itself. A job that finishes with one lane complete and
   the other unavailable is a job that did what it could, and saying so lane by
   lane is the only way to report that without either overclaiming or reading
   as a failure. */
function laneReport(name, lane, zone) {
  const read = Number(lane.records_ingested) || 0;

  switch (lane.state) {
    case "queued":
      return { tone: "wait", text: "Waiting for the worker" };
    case "running":
      return {
        tone: "wait",
        text: name === "local_zone"
          ? `Reading the ${zone} zone file`
          : "Reading scans already on file",
      };
    case "complete":
      return {
        tone: "good",
        text: read ? `Read in ${plural(read, "name")}` : "Nothing new to read in",
      };
    case "already_current":
      return { tone: "good", text: "Already indexed - nothing to re-read" };
    // Not a provider failure. One bounded pass landed, and the rest of the
    // history stays on the ordinary queue, which continues from the cursor
    // this run left behind. Saying "failed" here would be a lie about work
    // that succeeded and is still going.
    case "checkpointed":
      return {
        tone: "good",
        text: (read ? `Read in ${plural(read, "name")} so far.` : "Nothing new in this pass.")
          + " Older history is queued and lands on its own; nothing more to do here.",
      };
    case "unavailable":
      return { tone: "quiet", text: ENRICH_ABSENT[name] };
    case "failed":
      return { tone: "bad", text: "This one did not finish" };
    default:
      return null;
  }
}

function laneRow(name, report) {
  const row = document.createElement("div");
  row.className = "enrich-lane";
  row.dataset.tone = report.tone;

  const dot = document.createElement("span");
  dot.className = "enrich-dot";

  const label = document.createElement("span");
  label.className = "enrich-lane-name";
  label.textContent = ENRICH_NAMES[name];

  const text = document.createElement("span");
  text.className = "enrich-lane-text";
  text.textContent = report.text;

  row.append(dot, label, text);
  return row;
}

/* The summary is read off the lanes rather than off job.state. "partial" is
   the API's word for a job that is not wholly clean, and it covers both a lane
   that failed and a lane that checkpointed - one of which is bad news and one
   of which is not. Reporting them the same way would misinform. */
function laneSummary(job, reports) {
  if (job.state === "failed") return "Nothing could be read in.";
  const more = reports.some(([, report]) => report.more);
  const broke = reports.some(([, report]) => report.tone === "bad");
  const absent = reports.some(([, report]) => report.tone === "quiet");

  if (broke) {
    return more
      ? "Read in what was on hand. More is queued, and one source did not finish."
      : "Read in what was on hand. One source did not finish.";
  }
  if (more) return "Read in. Older history is queued and lands on its own.";
  if (absent) return "Read in what was on hand.";
  return "Read in.";
}

/* What a reader would actually hear as new. The lanes sit in a live region and
   a poll lands every couple of seconds, so redrawing an unchanged report would
   have a screen reader read the whole thing out again on every one of them. */
function laneSignature(job) {
  const lanes = job.lanes || {};
  const states = ENRICH_ORDER.map((name) => {
    const lane = lanes[name];
    return lane ? `${name}:${lane.state}:${lane.records_ingested || 0}` : `${name}:-`;
  });
  return `${states.join("|")}|${job.state}|${job.error || ""}`;
}

function renderLanes(job) {
  const signature = laneSignature(job);
  if (signature === enrich.laneSignature) return;
  enrich.laneSignature = signature;

  const zone = job.zone || (enrich.options && enrich.options.zone) || "zone";
  const lanes = job.lanes || {};
  const reports = [];

  for (const name of ENRICH_ORDER) {
    const lane = lanes[name];
    if (!lane) continue;
    const report = laneReport(name, lane, zone);
    // A lane nobody asked for has nothing to report.
    if (!report) continue;
    report.more = lane.state === "checkpointed";
    reports.push([name, report]);
  }

  const nodes = [];
  if (job.terminal) {
    const summary = document.createElement("p");
    summary.className = "enrich-summary";
    summary.textContent = laneSummary(job, reports);
    nodes.push(summary);
  }
  for (const [name, report] of reports) nodes.push(laneRow(name, report));

  if (job.terminal && job.error) {
    const why = document.createElement("div");
    why.className = "enrich-lane";
    why.dataset.tone = "bad";
    const dot = document.createElement("span");
    dot.className = "enrich-dot";
    const label = document.createElement("span");
    label.className = "enrich-lane-name";
    label.textContent = "Reported";
    const text = document.createElement("span");
    text.className = "enrich-lane-text";
    text.textContent = job.error;
    why.append(dot, label, text);
    nodes.push(why);
  }

  el.enrichLanes.replaceChildren(...nodes);
  el.enrichLanes.hidden = nodes.length === 0;
}

/* ── running one ─────────────────────────────────────────────────── */
async function submitEnrichment() {
  if (!enrich || enrich.busy || !enrich.selected.size) return;
  const apex = enrich.apex;
  // Sorted so that the same two actions always produce the same key, whichever
  // order the boxes were ticked in.
  const actions = [...enrich.selected].sort();

  enrich.busy = true;
  syncEnrichSubmit();
  setEnrichNote("");

  let response;
  try {
    response = await fetch(`${API_BASE}/v1/enrichment-jobs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "Idempotency-Key": idempotencyKey(apex, actions),
      },
      body: JSON.stringify({ apex, actions }),
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
  } catch {
    if (enrich && enrich.apex === apex) {
      enrich.busy = false;
      syncEnrichSubmit();
      // The key is kept: if the request did reach the API, retrying with it
      // rejoins that job rather than paying for a second one.
      setEnrichNote("Could not reach the index. Try again in a moment.", true);
    }
    return;
  }

  if (!enrich || enrich.apex !== apex) return;
  enrich.busy = false;
  // The submission spends one unit of the ordinary search allowance the first
  // time it is admitted, and the response says so; the meter should agree.
  setQuota(response.headers);

  if (response.status === 409) {
    // Either the key has been used for a different request, or an action stopped
    // being actionable while the reader was deciding. Both are answered the
    // same way: get the current options and offer what is actually left.
    forgetKey(apex, actions);
    const detail = await detailOf(response, "That is no longer available.");
    try {
      const options = await readEnrichmentOptions(apex);
      if (!enrich || enrich.apex !== apex) return;
      enrich.options = options;
      renderOffer();
    } catch {
      if (!enrich || enrich.apex !== apex) return;
    }
    setEnrichNote(sentence(detail), false);
    return;
  }

  if (response.status === 429) {
    const wait = retryAfter(response.headers, 60);
    setEnrichNote(
      `The daily allowance is spent, so this was not started. It resets in about ${plural(Math.ceil(wait / 60), "minute")}.`,
      true,
    );
    syncEnrichSubmit();
    return;
  }

  if (response.status === 503) {
    const wait = retryAfter(response.headers, 5);
    const detail = await detailOf(response, "The queue is not taking work right now.");
    setEnrichNote(`${sentence(detail)} Try again in about ${plural(wait, "second")}.`, true);
    syncEnrichSubmit();
    return;
  }

  if (!response.ok) {
    const detail = await detailOf(response, `The index refused this (${response.status}).`);
    setEnrichNote(sentence(detail), true);
    syncEnrichSubmit();
    return;
  }

  const job = await response.json();
  enrich.job = job;
  for (const name of actions) enrich.ran.add(name);
  enrich.lastActions = actions;
  enrich.jobUrl = response.headers.get("Location") || `/v1/enrichment-jobs/${job.job_id}`;
  enrich.until = Date.now() + ENRICH_WATCH_MS;

  // The offer is spent; from here the panel is a report.
  el.enrichActions.replaceChildren();
  el.enrichBlocked.hidden = true;
  el.enrichRun.hidden = true;
  el.enrichLede.textContent =
    `Reading records that already exist into the index. ${apex} is not contacted by any of it.`;
  renderLanes(job);

  if (job.terminal) {
    await finishEnrichment(job);
    return;
  }
  scheduleEnrichPoll(2);
}

function scheduleEnrichPoll(seconds) {
  if (!enrich) return;
  clearTimeout(enrich.timer);
  enrich.timer = setTimeout(pollEnrichment, seconds * 1000);
}

/* Watching costs nothing against the allowance - the status route identifies
   the requester but never admits a read - so the only thing to be careful
   about is how often, and for how long. */
async function pollEnrichment() {
  if (!enrich || !enrich.jobUrl) return;
  const apex = enrich.apex;

  let response;
  try {
    response = await fetch(`${API_BASE}${enrich.jobUrl}`, {
      headers: { Accept: "application/json" },
      signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
  } catch {
    if (enrich && enrich.apex === apex) scheduleEnrichPoll(5);
    return;
  }
  if (!enrich || enrich.apex !== apex) return;

  if (response.status === 503) {
    scheduleEnrichPoll(pollDelay(response.headers, 2));
    return;
  }
  if (!response.ok) {
    setEnrichNote(
      response.status === 404
        ? "This run is no longer on record. Search again to see where the index got to."
        : `Could not read the run's state (${response.status}).`,
      true,
    );
    el.enrichRun.hidden = false;
    el.enrichSubmit.hidden = true;
    return;
  }

  const job = await response.json();
  enrich.job = job;
  renderLanes(job);

  if (job.terminal) {
    await finishEnrichment(job);
    return;
  }

  if (Date.now() > enrich.until) {
    // Still going, but no longer worth a timer. The run continues on the
    // server either way; this only stops watching it.
    el.enrichRun.hidden = false;
    el.enrichSubmit.hidden = true;
    setEnrichNote("Still running. Search this domain again to pick up where it got to.");
    return;
  }

  scheduleEnrichPoll(pollDelay(response.headers, 2));
}

/* job.result_url is the unpaginated read. This page reads in pages of 500, so
   it goes back through that same path for the apex the job names rather than
   pulling a freshly imported zone into one response - which is the case the
   paging exists for. */
async function finishEnrichment(job) {
  clearTimeout(enrich.timer);
  enrich.timer = null;

  // A lane that failed can be asked for again. Nothing came of the attempt, and
  // the key naming it has to be released first or the API would rightly replay
  // the same finished job instead of starting a new one.
  const lanes = job.lanes || {};
  const broke = ENRICH_ORDER.filter((name) => lanes[name] && lanes[name].state === "failed");
  if (broke.length) {
    forgetKey(job.apex, enrich.lastActions);
    for (const name of broke) {
      enrich.ran.delete(name);
      enrich.retry.add(name);
    }
  }

  if (!job.result_url) return;

  CACHE.delete(job.apex);
  await search(job.apex, { push: false });

  if (!enrich || enrich.apex !== job.apex) return;
  // Anything still on hand is worth offering now that the record has moved.
  try {
    const options = await readEnrichmentOptions(job.apex);
    if (!enrich || enrich.apex !== job.apex) return;
    enrich.options = options;
    renderOffer();
  } catch { /* the report stands on its own */ }
}

/* Called at the end of every register render, so the panel follows the record
   rather than having to be torn down by every path that changes it. */
function syncEnrichment() {
  // A run that has already reported keeps its panel whether the record it
  // filled is empty or not: it is the account of where those names came from.
  if (enrich && enrich.apex === current.apex && enrich.job) {
    el.enrich.hidden = false;
    return;
  }
  if (!current.rows.length) {
    enrichmentFor(current.apex);
    return;
  }
  stopEnrichment();
}

el.enrichSubmit.addEventListener("click", submitEnrichment);

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
