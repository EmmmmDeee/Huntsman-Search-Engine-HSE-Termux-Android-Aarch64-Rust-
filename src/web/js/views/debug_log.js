import { API } from '/static/js/api.js';
import { $, esc, trunc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { pageHidden } from '/static/js/timers.js';

/* ═══════════ Page: DEBUG LOG (#/debuglog) — live tail of the verbose ring ═══════════

   The engine already tees its full TRACE-level output — the exact NDJSON that
   scrolls past in the Termux CLI — into a bounded in-memory ring
   (`util::log_capture`), previously reachable only as a whole-file DOWNLOAD
   from Settings. This view is the live counterpart: it polls
   GET /api/v1/logs/tail from a held cursor every 1.5s and appends only the new
   lines, so you can watch the debug log in the browser the way you watch it on
   the device.

   Each ring line is one flattened NDJSON object (`timestamp`, `level`,
   `target`, `line_number`, `message`, plus the event's own fields and span
   chain). We render it structurally — level-coloured, target:line tag, message,
   and the remaining fields expandable — with client-side level and
   target-substring filters. A line that is not JSON (there should be none, but
   the ring is bytes) is shown raw rather than dropped. When the server reports
   `missed>0` — lines evicted by the ring bound before this poll could read them
   — an honest gap marker is inserted instead of a silent skip. Loopback-only on
   the server side (the ring holds scan targets + discovered PII), so under a LAN
   bind this view simply shows the 403 rather than leaking. */

const POLL_MS = 1500;
// Cap rendered rows so a long session on a low-RAM device can't grow the DOM
// without bound — the ring itself is already bounded server-side; this bounds
// the view. Oldest rendered rows are evicted first, mirroring the ring.
const MAX_ROWS = 5000;
const LEVELS = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR'];

function st() {
  if (!S.debugLog) {
    S.debugLog = { cursor: 0, paused: false, level: 'TRACE', target: '', autoscroll: true, dropped: 0 };
  }
  return S.debugLog;
}

// Rank so a level filter of e.g. WARN shows WARN+ERROR. Unknown levels sort
// low (always shown) rather than being hidden by a stricter filter.
function levelRank(l) {
  const i = LEVELS.indexOf(String(l || '').toUpperCase());
  return i < 0 ? 0 : i;
}

function levelClass(l) {
  switch (String(l || '').toUpperCase()) {
    case 'ERROR': return 'dl-error';
    case 'WARN': return 'dl-warn';
    case 'INFO': return 'dl-info';
    case 'DEBUG': return 'dl-debug';
    default: return 'dl-trace';
  }
}

// Split a parsed NDJSON event into the columns we render explicitly and the
// "everything else" bag shown on expand. Copy so deleting keys never mutates
// anything retained.
function splitEvent(o) {
  const rest = Object.assign({}, o);
  const ts = rest.timestamp; delete rest.timestamp;
  const level = rest.level; delete rest.level;
  const target = rest.target; delete rest.target;
  const line = rest.line_number; delete rest.line_number;
  const message = rest.message; delete rest.message;
  return { ts, level, target, line, message, rest };
}

// Clock portion of an ISO timestamp (HH:MM:SS.mmm) — the date is noise for a
// live tail. Falls back to the raw value if it is not the expected shape.
function shortTs(ts) {
  const s = String(ts || '');
  const m = s.match(/T(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/);
  return m ? m[1] : s;
}

function rowHtml(line) {
  let o;
  try { o = JSON.parse(line); } catch { o = null; }
  if (o === null || typeof o !== 'object') {
    // Not JSON — show it raw rather than dropping it.
    return `<div class="dl-row dl-raw" data-level="TRACE" data-target="">${esc(line)}</div>`;
  }
  const { ts, level, target, line: ln, message, rest } = splitEvent(o);
  const tgt = target == null ? '' : String(target) + (ln != null ? ':' + ln : '');
  const restKeys = Object.keys(rest);
  const restStr = restKeys.length ? JSON.stringify(rest) : '';
  return `<div class="dl-row ${levelClass(level)}" data-level="${esc(String(level || 'TRACE').toUpperCase())}" data-target="${esc(tgt)}">`
    + `<span class="dl-ts">${esc(shortTs(ts))}</span>`
    + `<span class="dl-lvl">${esc(String(level || '').toUpperCase())}</span>`
    + `<span class="dl-tgt">${esc(trunc(tgt, 48))}</span>`
    + `<span class="dl-msg">${esc(message == null ? '' : String(message))}</span>`
    + (restStr ? `<span class="dl-fields">${esc(trunc(restStr, 400))}</span>` : '')
    + `</div>`;
}

// Apply the current level + target filters to already-rendered rows (client
// side, so changing a filter is instant and doesn't refetch).
function applyFilters() {
  const s = st();
  const min = levelRank(s.level);
  const needle = s.target.trim().toLowerCase();
  const box = $('#dl-box');
  if (!box) return;
  let shown = 0;
  box.querySelectorAll('.dl-row').forEach(r => {
    const okLevel = levelRank(r.getAttribute('data-level')) >= min;
    const okTarget = !needle || (r.getAttribute('data-target') || '').toLowerCase().includes(needle);
    const vis = okLevel && okTarget;
    r.style.display = vis ? '' : 'none';
    if (vis) shown++;
  });
  const c = $('#dl-count');
  if (c) c.textContent = `${shown} shown`;
}

function append(lines, missed) {
  const box = $('#dl-box');
  if (!box) return;
  const empty = box.querySelector('.empty-state');
  if (empty) empty.remove();
  let html = '';
  if (missed > 0) {
    html += `<div class="dl-row dl-gap" data-level="ERROR" data-target="">`
      + `— ${missed} line(s) lost (ring evicted them before this poll) —</div>`;
  }
  for (const l of lines) html += rowHtml(l);
  box.insertAdjacentHTML('beforeend', html);
  // Bound the DOM: drop oldest rows past the cap.
  let rows = box.children;
  while (rows.length > MAX_ROWS) box.removeChild(rows[0]);
  applyFilters();
  const s = st();
  if (s.autoscroll) box.scrollTop = box.scrollHeight;
}

async function poll() {
  const s = st();
  if (s.paused || pageHidden()) return;
  let res;
  try {
    res = await API.logsTail(s.cursor);
  } catch (e) {
    const status = $('#dl-status');
    if (status) { status.className = 'label label-danger'; status.textContent = 'error'; }
    return;
  }
  s.cursor = res.cursor != null ? res.cursor : s.cursor;
  s.dropped = res.dropped || 0;
  const status = $('#dl-status');
  if (status) { status.className = 'label label-success'; status.textContent = s.paused ? 'paused' : 'live'; }
  const drop = $('#dl-dropped');
  if (drop) drop.textContent = s.dropped ? `${s.dropped} evicted` : '';
  if ((res.lines && res.lines.length) || res.missed) append(res.lines || [], res.missed || 0);
}

export function clearDebugLogTimerLocal() {
  if (S.debugLogTimer) { clearInterval(S.debugLogTimer); S.debugLogTimer = null; }
}

export async function renderDebugLog(v) {
  const s = st();
  // A fresh view of the tail starts from the ring's current tail rather than
  // replaying the whole buffer — the Download button (Settings / the link here)
  // is for the full ring; this is "what's happening now". Reset the cursor to 0
  // ONLY so the first poll's `missed` correctly reports how much history the
  // ring already dropped; we then render from there forward.
  s.cursor = 0;

  v.innerHTML = `
    <div class="crumbs"><a href="#/dash">Dashboard</a> &raquo; Debug Log</div>
    <h2>Debug Log <small class="text-muted">live tail of the engine's verbose (TRACE) log — the same stream as the Termux CLI</small></h2>
    <hr style="margin:8px 0 12px 0">
    <div class="panel panel-default">
      <div class="panel-heading">
        <b>Live tail</b>
        <span id="dl-status" class="label label-default">connecting…</span>
        <span id="dl-dropped" class="text-muted" style="font-size:11px;margin-left:6px"></span>
        <div class="pull-right" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          <select id="dl-level" class="form-control input-sm" style="width:auto" title="Minimum level to show">
            ${LEVELS.map(l => `<option value="${l}"${l === s.level ? ' selected' : ''}>${l}+</option>`).join('')}
          </select>
          <input id="dl-target" class="form-control input-sm" style="width:150px" placeholder="filter target…" value="${esc(s.target)}">
          <span id="dl-count" class="text-muted" style="font-size:11px">0 shown</span>
          <label style="font-size:11px;margin:0"><input type="checkbox" id="dl-autoscroll"${s.autoscroll ? ' checked' : ''}> follow</label>
          <button class="btn btn-default btn-xs" id="dl-pause">${s.paused ? 'Resume' : 'Pause'}</button>
          <button class="btn btn-default btn-xs" id="dl-clear">Clear view</button>
          <a class="btn btn-default btn-xs" href="${API.logsUrl()}" download data-download data-download-name="hse-debug.log" title="Download the complete ring buffer as a .log file"><i class="glyphicon glyphicon-download-alt"></i></a>
        </div>
      </div>
      <div class="panel-body" style="padding:0">
        <div id="dl-box" class="dl-box"><div class="empty-state"><p>Waiting for log output… run a scan (or any command) to see live TRACE events here.</p></div></div>
      </div>
    </div>
  `;

  $('#dl-level').addEventListener('change', e => { s.level = e.target.value; applyFilters(); });
  $('#dl-target').addEventListener('input', e => { s.target = e.target.value; applyFilters(); });
  $('#dl-autoscroll').addEventListener('change', e => { s.autoscroll = e.target.checked; });
  $('#dl-pause').addEventListener('click', e => {
    s.paused = !s.paused;
    e.target.textContent = s.paused ? 'Resume' : 'Pause';
    const status = $('#dl-status');
    if (status) { status.className = s.paused ? 'label label-warning' : 'label label-success'; status.textContent = s.paused ? 'paused' : 'live'; }
  });
  $('#dl-clear').addEventListener('click', () => {
    // Clears only what THIS view shows; the server ring is untouched (the cursor
    // stays put, so the next poll continues from where the stream is).
    const box = $('#dl-box');
    if (box) box.innerHTML = '';
    applyFilters();
  });

  // Kick an immediate poll, then schedule. Torn down by render() via
  // clearDebugLogTimer() (timers.js), so navigation never leaves it firing.
  clearDebugLogTimerLocal();
  await poll();
  S.debugLogTimer = setInterval(poll, POLL_MS);
}
