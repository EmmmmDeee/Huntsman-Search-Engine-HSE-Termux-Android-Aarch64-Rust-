import { $, esc, fmtClock, kindPill, saveShownRows } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { API } from '/static/js/api.js';

/* ── Scan Log (history + live SSE) ──
   v0.10+ — engine persists every event to SQLite, so completed scans
   now show the full timeline. For live scans we must take care with
   the SSE-vs-history ordering:

   Engine semantics: persist FIRST, then broadcast. So every event on
   the bus is already persisted; an event in history may not yet have
   been broadcast.

   Two ordering choices and their failure modes:
   - Fetch history first, then subscribe SSE → events broadcast in
     the gap between fetch-return and SSE-subscribe are MISSED. Bad.
   - Subscribe SSE first, then fetch history → events broadcast in
     the gap appear in BOTH (in SSE buffer, and in the history rows
     persisted just before broadcast). Need dedup, but no loss.

   We go with subscribe-first and a count-based content-fingerprint
   dedup. Limitation: if a new event happens to have IDENTICAL kind
   JSON to an already-rendered history row AND arrives via SSE after
   the history fetch returned, it gets falsely deduped. Mitigating
   factor: this is rare in practice (events for the same module emit
   per-target, and targets vary across rounds) and a proper fix needs
   a monotonic per-event id on the engine side. */
export async function renderLog(host, scan){
  const running = scan.status==='running' || scan.status==='pending';
  // Fresh tally per view — otherwise opening a second scan's log would add its
  // events to the previous scan's breakdown. The eviction counter resets with
  // it, for the same reason: it describes THIS view's box.
  typeCounts.clear();
  logRowsDropped = 0;
  host.innerHTML = `
    <div class="panel panel-default">
      <div class="panel-heading">
        <b>Event log</b>
        <div class="pull-right">
          <span id="log-status" class="label label-default">loading…</span>
          &nbsp;<a class="btn btn-default btn-xs" href="${API.eventsLogUrl(scan.id)}" download data-download
                 title="Download the complete persisted scan event log as a .log file — works while a scan is still running"><i class="glyphicon glyphicon-download-alt"></i>&nbsp;Download</a>
          &nbsp;<button class="btn btn-default btn-xs" id="log-save-shown"
                 title="Save exactly the events shown here to a .log file — captures a live/streaming scan and works even if the server history failed to load">Save shown</button>
          &nbsp;<button class="btn btn-default btn-xs" id="log-clear">Clear</button>
        </div>
      </div>
      <div class="panel-body" style="padding:0">
        <div id="log-bytype" class="text-muted"
             style="display:none;padding:6px 10px;border-bottom:1px solid var(--border,#eee);font-size:11px"></div>
        <div id="log-box"><div class="empty-state"><p>Fetching event history…</p></div></div>
      </div>
    </div>
  `;
  // Clearing the rows clears the breakdown with them — it describes what is
  // shown, so leaving stale counts above an empty box would misreport.
  $('#log-clear').addEventListener('click', ()=>{
    $('#log-box').innerHTML='';
    typeCounts.clear();
    logRowsDropped = 0;
    renderTypeCounts();
  });
  // "Save shown" — serialise exactly the rendered rows to a .log file. This is
  // the always-available path: it captures a live/streaming scan's rows as they
  // appear, and works even when the server-side history fetch failed (the
  // `historyError` branch below) where the `.log` download may be empty.
  $('#log-save-shown').addEventListener('click', ()=>saveShownRows('#log-box', {
    emptyMsg: 'No events shown yet — nothing to save.',
    header: (n) =>
      `# HSE scan event log (as shown in the browser)\n` +
      `# scan ${scan.id}\n` +
      `# ${n} event(s)` + (running ? ' — live capture, may be partial\n' : '\n') +
      // The box is row-capped, so "as shown" can be a suffix of the scan. Say
      // so in the artifact itself — a saved log that silently omits its start
      // is worse than no log, and the complete one is a click away.
      (logRowsDropped
        ? `# NOTE: the oldest ${logRowsDropped} row(s) were dropped from view (display cap ${LOG_MAX_ROWS});\n` +
          `#       this file starts mid-scan. Use the Download button for the complete log.\n`
        : '') + `\n`,
    filename: `hse-events-shown-${scan.id.slice(0, 12)}.log`,
  }));

  // 1) Subscribe to SSE FIRST so events broadcast during the
  //    history fetch are captured in the `buffered` array rather
  //    than lost. Switch to direct-render once history is rendered.
  const buffered = [];
  let bufferingMode = true;
  const status = $('#log-status');
  if (running){
    status.className = 'label label-info';
    status.innerHTML = '<i class="glyphicon glyphicon-record"></i>&nbsp;live';
    // When the tailed scan finishes DURING the stream, its terminal
    // `scan_complete` event arrives here. The one-shot `!running` block further
    // down only runs for a scan already finished at render time, so without
    // this the pill would sit 'live'/'reconnecting…' forever. Reflect the true
    // terminal state (carried on the event since the ScanComplete status fix)
    // and close the stream — `scan_complete` is the last event, so closing
    // after it drops nothing.
    const onTerminal = ev => {
      const st = $('#log-status'); if (!st) return;
      const term = ev.status || 'complete';
      st.className = term === 'failed' ? 'label label-danger'
                   : term === 'aborted' ? 'label label-warning'
                   : 'label label-default';
      st.textContent = term === 'failed' ? 'failed'
                     : term === 'aborted' ? 'aborted'
                     : 'complete';
      closeSse();
    };
    openSse(scan.id, ev=>{
      if (bufferingMode) buffered.push(ev);
      else appendLog(ev);
      if (ev && ev.type === 'scan_complete') onTerminal(ev);
    }, (state, es)=>{
      const st = $('#log-status'); if (!st) return;
      // Once the scan has finished we close the stream and set a terminal pill;
      // ignore the reconnect/close state flaps that closing itself triggers so
      // they can't overwrite it (closeSse nulls S.sse).
      if (!S.sse) return;
      if (state === 'open'){
        st.className = 'label label-info';
        st.innerHTML = '<i class="glyphicon glyphicon-record"></i>&nbsp;live';
      } else if (es.readyState === 2){ // CLOSED — server idle-closed or unreachable
        st.className = 'label label-default';
        st.textContent = 'disconnected';
      } else { // CONNECTING — auto-reconnecting
        st.className = 'label label-warning';
        st.textContent = 'reconnecting…';
      }
    });
  }

  // 2) Pull the persistent history. Surface fetch failures explicitly
  //    so a completed scan with events on disk doesn't silently
  //    render "No events recorded".
  let history = [];
  let historyError = null;
  try {
    const r = await fetch('/api/v1/scans/'+encodeURIComponent(scan.id)+'/events.history');
    if (r.ok){
      const j = await r.json();
      history = j.events || [];
    } else {
      historyError = `HTTP ${r.status}`;
    }
  } catch (e) {
    historyError = e && e.message ? e.message : String(e);
  }

  // 3) Render history and build a per-fingerprint count map. Each
  //    history row contributes one "expected duplicate" credit so the
  //    next SSE-buffered event with the same fingerprint is treated
  //    as the broadcast copy of an already-rendered history row.
  const box = $('#log-box');
  const histCounts = new Map();
  if (historyError){
    // History fetch failed: we can't compute dedup credits, so we
    // also can't sensibly drain the buffered SSE events without
    // potentially double-painting (or missing) rows. Surface the
    // error alone — the operator's next refresh has another shot
    // at history, and `openSse` callback below will start adding
    // fresh rows the moment we switch out of buffering mode.
    box.innerHTML = `<div class="alert alert-danger" style="margin:8px">Failed to load event history: ${esc(historyError)}</div>`;
    bufferingMode = false;
    if (!running){
      status.className = 'label label-warning';
      status.textContent = 'history error';
    }
    return;
  }
  if (history.length === 0 && !running){
    box.innerHTML = `<div class="empty-state"><p>No events recorded for this scan.</p></div>`;
  } else {
    box.innerHTML = '';
    for (const ev of history){
      const kind = ev.kind || ev;
      const fp = JSON.stringify(kind);
      histCounts.set(fp, (histCounts.get(fp) || 0) + 1);
      // The persisted row has { scan_id, ts, kind }. mapEvent reads
      // ev.type plus ev.* — the EventKind variant is flattened with
      // `#[serde(tag="type")]`, so passing ev.kind through works.
      appendLog(kind, ev.ts);
    }
  }

  // 4) Drain buffered SSE events. Each one with a fingerprint that
  //    still has unspent history credits is the broadcast twin of
  //    an already-rendered row — skip it. Events with no credits
  //    (either fingerprint never seen in history, or all history
  //    twins already accounted for) get rendered.
  const consumed = new Map();
  for (const ev of buffered){
    const fp = JSON.stringify(ev);
    const histCount = histCounts.get(fp) || 0;
    const consumedCount = consumed.get(fp) || 0;
    if (consumedCount < histCount){
      consumed.set(fp, consumedCount + 1);
    } else {
      appendLog(ev);
    }
  }
  bufferingMode = false;

  if (!running){
    status.className = 'label label-default';
    status.textContent = history.length ? `${history.length} events` : 'not streaming';
  }
}
/* ── "By type" breakdown ──
   Both on-disk (render_event_log) and streaming (SSE) events carry the same
   kind (event type), so the browser can tally them client-side — same breakdown
   on-disk and on-screen. The timeline alone left the operator to count 764
   rows by eye; the breakdown answers "how many entities / errors was that?"
   at a glance, kept live as rows stream in, at zero extra round-trip cost. */
const typeCounts = new Map();
export function bumpTypeCount(type){
  if (!type) return;
  typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
}
export function renderTypeCounts(){
  const host = $('#log-bytype'); if (!host) return;
  if (!typeCounts.size){ host.style.display = 'none'; return; }
  // Sorted by type name, matching render_event_log's BTreeMap ordering so the
  // on-screen breakdown lists in the same order as the downloaded log.
  const parts = Array.from(typeCounts.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([t, n]) => `<span style="display:inline-block;margin-right:12px"><code>${esc(t)}</code> <b>${n}</b></span>`);
  const total = Array.from(typeCounts.values()).reduce((a, b) => a + b, 0);
  // These totals count EVENTS, not rows on screen — `bumpTypeCount` runs
  // before any eviction — so they stay true for the whole scan even once the
  // box is capped. When rows have been dropped, say so here rather than let
  // the operator infer the timeline is complete from a complete breakdown.
  const dropped = logRowsDropped
    ? ` <span class="text-muted" title="The rendered timeline is capped at ${LOG_MAX_ROWS} rows to keep the page responsive on a phone. These per-type totals still cover every event; use Download for the complete log.">· oldest ${logRowsDropped} row${logRowsDropped===1?'':'s'} dropped from view (Download has all)</span>`
    : '';
  host.innerHTML = `<b>By type</b> <span style="margin-right:12px">(${total} event${total===1?'':'s'})</span>${parts.join('')}${dropped}`;
  host.style.display = '';
}

/* Coalesce the per-row DOM work that does not have to happen per row.
   `appendLog` runs once per event, and a real scan emits hundreds (a captured
   run: 598 events, 371 of them entity_found). Re-sorting the type histogram and
   rewriting its `innerHTML` on every one of those, then reading
   `box.scrollHeight` — which forces a synchronous layout — turned each event
   into a full re-render plus a forced reflow. On a memory- and CPU-constrained
   Termux/Android browser that is the difference between a scan that streams and
   a tab that dies.

   Both operations are idempotent and only the LAST one is observable, so they
   are deferred to one animation frame. The end state is byte-identical: every
   event is still counted (`bumpTypeCount` stays synchronous, above), the
   breakdown still shows every event, and the box still ends scrolled to the
   newest row. */
/* Hard bound on how many rows the log box holds at once.

   Every event previously became a permanent DOM node: three spans inside a
   div, kept for the life of the view, with nothing ever removed. Captured
   runs already reach 598 events (371 of them entity_found) and this file's
   own "By type" note records a 764-row log; DEFAULT_SCAN_DEPTH went 3→5 in
   #315, so a deep scan's event count is several times that. On a no-root
   Termux/Android browser — the only platform this ships to — an unbounded,
   monotonically growing node list under a live SSE stream is the classic way
   to lose the tab.

   1200 sits deliberately above every run observed so far, so a normal scan
   evicts nothing at all and looks exactly as it did; only the pathological
   tail is bounded. Eviction is from the top (oldest first), which is the
   right end to lose: the newest rows are the ones an operator is watching.

   Nothing is silently lost. The "By type" breakdown counts events, not rows
   (`bumpTypeCount` runs before any eviction), so it keeps reporting the true
   totals for the whole scan; the drop is disclosed there and in the "Save
   shown" header; and the complete persisted log is always one click away on
   the Download button, which streams it from the server. */
const LOG_MAX_ROWS = 1200;
let logRowsDropped = 0;

let logFlushScheduled = false;
function scheduleLogFlush(){
  if (logFlushScheduled) return;
  logFlushScheduled = true;
  const flush = ()=>{
    logFlushScheduled = false;
    renderTypeCounts();
    const b = $('#log-box');
    if (b) b.scrollTop = b.scrollHeight;
  };
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(flush);
  else setTimeout(flush, 0);
}

export function appendLog(ev, ts){
  const box = $('#log-box'); if (!box) return;
  // Count every rendered row exactly once — history rows and live SSE rows both
  // land here — so the breakdown always describes precisely what is on screen.
  bumpTypeCount(ev && ev.type);
  const m = mapEvent(ev);
  const row = document.createElement('div');
  row.className = `log-row lv-${m.lv}`;
  // Use the event's recorded ts if we have it (history rows); fall
  // back to wall-clock for live rows.
  const t = ts ? (new Date(ts*1000)).toTimeString().slice(0,8) : fmtClock();
  row.innerHTML = `<span class="ts">${esc(t)}</span><span class="typ">${esc(m.typ)}</span><span class="msg">${m.msg}</span>`;
  box.appendChild(row);
  // Evict oldest-first the moment we exceed the cap. Synchronous rather than
  // deferred to the flush below: the history render appends its whole result
  // set in one synchronous loop, so a deferred trim would still let the full
  // unbounded list exist for a frame — and it is the peak, not the steady
  // state, that takes the tab down.
  while (box.childElementCount > LOG_MAX_ROWS && box.firstElementChild){
    box.removeChild(box.firstElementChild);
    logRowsDropped++;
  }
  scheduleLogFlush();
}
/* `''` or `'s'` for a counted noun — the browser-side twin of the Rust
   renderers' `plural()`. A live scan routinely reports exactly one of
   something, and "1 probes" is the kind of detail that makes an operator
   distrust the number beside it. */
const plural = n => (Number(n) === 1 ? '' : 's');

/** Map a structured JSON event (from the event log or SSE stream) to an
 * on-screen log line object: {typ, lv, msg}. The Rust event carries:
 * — time/level/kind (top-level) + per-variant concise fields (JSON structure)
 * — no glyphs, no decorative characters (clean, machine-readable)
 * This function extracts the fields and builds a human-readable msg, using
 * `typ` (category: module/entity/expand/corr/live), `lv` (level color:
 * info/ok/warn/err/skip/corr), and `msg` (the formatted summary).
 */
export function mapEvent(ev){
  const t = ev.type;
  if (t==='module_start')   return {typ:'module', lv:'info',  msg:`${esc(ev.module)}: running`};
  if (t==='module_done')    return {typ:'module', lv:'ok',    msg:`${esc(ev.module)}: done <span class="text-muted">(${ev.found} found)</span>`};
  if (t==='module_error')   return {typ:'module', lv:'err',   msg:`${esc(ev.module)}: error <span class="text-muted">${esc(ev.error)}</span>`};
  if (t==='module_skipped') return {typ:'module', lv:'skip',  msg:`${esc(ev.module)}: skipped <span class="text-muted">${esc(ev.reason)}</span>`};
  // Confidence and the candidate marker are part of the line, not decoration:
  // the Rust twin renders them in the JSON fields (confidence as a rounded
  // number, candidate as a boolean), and the downloaded events.log
  // / debug-bundle sequence therefore carry both. We extract them from the
  // structured event and show them here so on-screen and on-disk logs agree.
  if (t==='entity_found'){
    const conf = typeof ev.confidence === 'number' ? ev.confidence.toFixed(2) : null;
    const cand = ev.candidate ? ' <span class="text-muted">(candidate)</span>' : '';
    return {typ:'entity', lv:'found',
      msg:`${kindPill(ev.entity_kind)} ${esc(ev.value)}${conf!=null?` <span class="text-muted">·${esc(conf)}</span>`:''}${cand}`};
  }
  if (t==='scan_start')     return {typ:'scan',   lv:'info',  msg:`scan started: ${esc(ev.target_kind)}=${esc(ev.target_value)}`};
  // Mirrors the three-way branch in the Rust twin (core/event/mod.rs): a
  // cancelled or failed scan emits this same terminal event, so it must not
  // read as a green success. `ev.status` is absent on event rows persisted
  // before the field existed — those were all genuine completions, so default
  // to 'complete'.
  if (t==='scan_complete'){
    const st = ev.status || 'complete';
    if (st==='aborted') return {typ:'scan', lv:'warn', msg:`scan aborted — stopped early, ${ev.entities} entities`};
    if (st==='failed')  return {typ:'scan', lv:'err',  msg:`scan failed`};
    return {typ:'scan', lv:'ok', msg:`scan complete, ${ev.entities} entities`};
  }
  if (t==='expansion_tick') return {typ:'expand', lv:'info',  msg:`expansion: depth ${ev.depth}, queued ${ev.queued}, visited ${ev.visited}`};
  if (t==='expansion_stop') return {typ:'expand', lv:'warn',  msg:`expansion stopped: ${esc(ev.reason)}`};
  if (t==='entity_excluded') return {typ:'expand', lv:'skip', msg:`not expanded: ${kindPill(ev.entity_kind)} ${esc(ev.value)} <span class="text-muted">${esc(ev.reason)}</span>`};
  // Final bulk breach sweep. `dropped` is part of the line, not a tooltip: a
  // capped plan and a complete one must not read the same.
  if (t==='breach_sweep')   return {typ:'expand', lv:'info',  msg:`breach sweep: ${ev.probes} probe${plural(ev.probes)} from ${ev.anchors} anchor${plural(ev.anchors)}${ev.dropped?` <span class="text-muted">(${ev.dropped} over cap)</span>`:''}`};
  // Autonomous audit of the breach corpus. A non-passing verdict means two
  // corpora contradict each other, so it renders at warn level.
  if (t==='consensus_audit') return {typ:'corr', lv:(ev.verdict==='PASS'||ev.verdict==='PASS_WITH_WARNINGS')?'ok':'warn', msg:`breach audit: ${esc(ev.verdict)}, ${ev.corroborated}/${ev.examined} corroborated <span class="text-muted">${ev.flags} flag${plural(ev.flags)}</span>`};
  if (t==='correlation_found') return {typ:'corr', lv:'corr', msg:`${esc(ev.rule||ev.rule_id||'?')}`};
  if (t==='correlations_done') return {typ:'corr', lv:'info', msg:`correlations: ${ev.count} evaluated`};
  // Live-session lifecycle (streamed into the Live-activity panel). Without
  // these the panel rendered each as raw JSON via the fallback below.
  if (t==='live_start')     return {typ:'live',   lv:'info',  msg:`live session started: ${esc(ev.target_kind)}=${esc(ev.target_value)} <span class="text-muted">every ${esc(ev.interval_secs)}s</span>`};
  if (t==='live_tick')      return {typ:'live',   lv:'info',  msg:`sweep #${esc(ev.iteration)}`};
  if (t==='live_stop')      return {typ:'live',   lv:'warn',  msg:`live session stopped: <span class="text-muted">${esc(ev.reason)}</span>`};
  return {typ: esc(t||'?'), lv:'info', msg: esc(JSON.stringify(ev).slice(0,220))};
}
export function openSse(scanId, onEv, onState){
  closeSse();
  const es = new EventSource('/api/v1/scans/'+encodeURIComponent(scanId)+'/events');
  es.onmessage = e => { try { onEv(JSON.parse(e.data)); } catch {} };
  if (onState){
    // EventSource auto-reconnects on its own; we only reflect the state so a
    // dropped stream on a flaky mobile link doesn't look frozen-but-live.
    es.onopen  = () => onState('open', es);
    es.onerror = () => onState('error', es);
  }
  S.sse = es;
}
export function closeSse(){ if (S.sse){ S.sse.close(); S.sse = null; } }

/* Per-session live stream — a SECOND SSE slot, kept separate from the scan-log
   S.sse, so the Live Monitor can tail a running session's events (its own
   lifecycle plus every per-iteration scan it spawns) via /live/{id}/events
   without clobbering, or being clobbered by, an open scan log. */
export function openLiveSse(liveId, onEv){
  closeLiveSse();
  const es = new EventSource('/api/v1/live/'+encodeURIComponent(liveId)+'/events');
  es.onmessage = e => { try { onEv(JSON.parse(e.data)); } catch {} };
  S.liveSse = es;
  return es;
}
export function closeLiveSse(){ if (S.liveSse){ S.liveSse.close(); S.liveSse = null; } }

