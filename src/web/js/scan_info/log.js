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
        <div id="log-box"><div class="empty-state"><p>Fetching event history…</p></div></div>
      </div>
    </div>
  `;
  $('#log-clear').addEventListener('click', ()=>{ $('#log-box').innerHTML=''; });
  // "Save shown" — serialise exactly the rendered rows to a .log file. This is
  // the always-available path: it captures a live/streaming scan's rows as they
  // appear, and works even when the server-side history fetch failed (the
  // `historyError` branch below) where the `.log` download may be empty.
  $('#log-save-shown').addEventListener('click', ()=>saveShownRows('#log-box', {
    emptyMsg: 'No events shown yet — nothing to save.',
    header: (n) =>
      `# HSE scan event log (as shown in the browser)\n` +
      `# scan ${scan.id}\n` +
      `# ${n} event(s)` + (running ? ' — live capture, may be partial\n' : '\n') + `\n`,
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
    openSse(scan.id, ev=>{
      if (bufferingMode) buffered.push(ev);
      else appendLog(ev);
    }, (state, es)=>{
      const st = $('#log-status'); if (!st) return;
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
export function appendLog(ev, ts){
  const box = $('#log-box'); if (!box) return;
  const m = mapEvent(ev);
  const row = document.createElement('div');
  row.className = `log-row lv-${m.lv}`;
  // Use the event's recorded ts if we have it (history rows); fall
  // back to wall-clock for live rows.
  const t = ts ? (new Date(ts*1000)).toTimeString().slice(0,8) : fmtClock();
  row.innerHTML = `<span class="ts">${esc(t)}</span><span class="typ">${esc(m.typ)}</span><span class="msg">${m.msg}</span>`;
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}
/* `''` or `'s'` for a counted noun — the browser-side twin of the Rust
   renderers' `plural()`. A live scan routinely reports exactly one of
   something, and "1 probes" is the kind of detail that makes an operator
   distrust the number beside it. */
const plural = n => (Number(n) === 1 ? '' : 's');

export function mapEvent(ev){
  const t = ev.type;
  if (t==='module_start')   return {typ:'module', lv:'info',  msg:`▶ ${esc(ev.module)}`};
  if (t==='module_done')    return {typ:'module', lv:'ok',    msg:`✓ ${esc(ev.module)} <span class="text-muted">(${ev.found} found)</span>`};
  if (t==='module_error')   return {typ:'module', lv:'err',   msg:`✗ ${esc(ev.module)} <span class="text-muted">${esc(ev.error)}</span>`};
  if (t==='module_skipped') return {typ:'module', lv:'skip',  msg:`◌ ${esc(ev.module)} <span class="text-muted">${esc(ev.reason)}</span>`};
  if (t==='entity_found')   return {typ:'entity', lv:'found', msg:`${kindPill(ev.entity?.kind)} ${esc(ev.entity?.value)}`};
  if (t==='scan_start')     return {typ:'scan',   lv:'info',  msg:`scan started · ${esc(ev.target_kind)}=${esc(ev.target_value)}`};
  if (t==='scan_complete')  return {typ:'scan',   lv:'ok',    msg:`scan complete · ${ev.entity_count} entities`};
  if (t==='expansion_tick') return {typ:'expand', lv:'info',  msg:`depth ${ev.depth} · queued ${ev.queued} · visited ${ev.visited}`};
  if (t==='expansion_stop') return {typ:'expand', lv:'warn',  msg:`expansion stopped · ${esc(ev.reason)}`};
  if (t==='entity_excluded') return {typ:'expand', lv:'skip', msg:`⊘ not expanded · ${kindPill(ev.kind)} ${esc(ev.value)} <span class="text-muted">${esc(ev.reason)}</span>`};
  // Final bulk breach sweep. `dropped` is part of the line, not a tooltip: a
  // capped plan and a complete one must not read the same.
  if (t==='breach_sweep')   return {typ:'expand', lv:'info',  msg:`⇉ breach sweep · ${ev.probes} probe${plural(ev.probes)} from ${ev.anchors} anchor${plural(ev.anchors)}${ev.dropped?` <span class="text-muted">(${ev.dropped} over cap)</span>`:''}`};
  // Autonomous audit of the breach corpus. A non-passing verdict means two
  // corpora contradict each other, so it renders at warn level.
  if (t==='consensus_audit') return {typ:'corr', lv:(ev.verdict==='PASS'||ev.verdict==='PASS_WITH_WARNINGS')?'ok':'warn', msg:`⚖ breach audit · ${esc(ev.verdict)} · ${ev.corroborated}/${ev.examined} corroborated <span class="text-muted">${ev.flags} flag${plural(ev.flags)}</span>`};
  if (t==='correlation_found') return {typ:'corr', lv:'corr', msg:`${esc(ev.correlation?.rule_name||ev.correlation?.rule_id||'?')}`};
  if (t==='correlations_done') return {typ:'corr', lv:'info', msg:`correlations done · ${ev.count}`};
  // Live-session lifecycle (streamed into the Live-activity panel). Without
  // these the panel rendered each as raw JSON via the fallback below.
  if (t==='live_start')     return {typ:'live',   lv:'info',  msg:`▶ live session started · ${esc(ev.target_kind)}=${esc(ev.target_value)} <span class="text-muted">every ${esc(ev.interval_secs)}s</span>`};
  if (t==='live_tick')      return {typ:'live',   lv:'info',  msg:`↻ iteration ${esc(ev.iteration)}`};
  if (t==='live_stop')      return {typ:'live',   lv:'warn',  msg:`■ live session stopped <span class="text-muted">${esc(ev.reason)}</span>`};
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

