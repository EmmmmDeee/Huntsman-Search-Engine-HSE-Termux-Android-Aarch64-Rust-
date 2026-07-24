import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtClock, fmtDate, kindPill, saveShownRows, statusPill, toast } from '/static/js/helpers.js';
import { closeLiveSse, mapEvent, openLiveSse } from '/static/js/scan_info/log.js';
import { S, TARGET_KINDS } from '/static/js/state.js';
import { clearLiveTimer } from '/static/js/timers.js';
import { render } from '/static/js/main.js';

export function wireLiveStops(){
  $$('button[data-livestop]').forEach(b=>b.addEventListener('click', async ()=>{
    try { await API.liveStop(b.dataset.livestop); toast('Stopping session'); render(); }
    catch(e){ if (typeof alertify !== 'undefined') alertify.error(e.message); }
  }));
}
/* Wire each session row's "Stream" button to tail that session's live events.
   Re-called after every 8s poll re-render (the buttons live inside the polled
   #live-sessions host), so handlers are always fresh. */
export function wireLiveStreams(){
  $$('button[data-livestream]').forEach(b=>b.addEventListener('click', ()=>{
    openLiveStream(b.dataset.livestream, b.dataset.lval || b.dataset.livestream);
  }));
}
/* Tail a live session's event stream into the persistent "Live activity" panel.
   The panel lives OUTSIDE the 8s-polled #live-sessions table, so the poll's
   re-render never tears an open stream down. */
export function openLiveStream(id, label){
  S.streamLiveId = id;
  const panel = $('#live-stream-panel'), host = $('#live-stream-host'), lab = $('#live-stream-label');
  if (lab) lab.textContent = ' — ' + label;
  if (host) host.innerHTML = '<div class="text-muted">Waiting for events…</div>';
  if (panel) panel.style.display = '';
  let first = true;
  openLiveSse(id, ev => {
    if (first){ if (host) host.innerHTML = ''; first = false; }
    appendLiveLog(ev);
  });
}
export function closeLiveStream(){
  closeLiveSse();
  S.streamLiveId = null;
  const panel = $('#live-stream-panel'); if (panel) panel.style.display = 'none';
}
/* Append one streamed event to the Live-activity panel, reusing the scan-log
   event mapper. The tail is bounded so a long-running radar can't grow the DOM
   without limit. */
export function appendLiveLog(ev){
  const box = $('#live-stream-host'); if (!box) return;
  const m = mapEvent(ev);
  const row = document.createElement('div');
  row.className = `log-row lv-${m.lv}`;
  row.innerHTML = `<span class="ts">${esc(fmtClock())}</span><span class="typ">${esc(m.typ)}</span><span class="msg">${m.msg}</span>`;
  box.appendChild(row);
  while (box.childElementCount > 300) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}
/* Save exactly the rows currently shown in the Live-activity panel to a .log
   file — the always-available path for a streaming session (there is no
   persisted per-session log endpoint), mirroring the scan-log "Save shown". */
export function saveLiveShown(){
  saveShownRows('#live-stream-host', {
    emptyMsg: 'No live activity shown yet — nothing to save.',
    header: (n) => `# HSE live-session activity (as shown in the browser)\n# ${n} event(s) — live capture, may be partial\n\n`,
    filename: 'hse-live-activity.log',
  });
}
export function renderLiveSessions(sessions){
  if (!sessions.length){
    return '<div class="empty-state"><h3>No active sessions</h3>'
      + '<p>Start one above to continuously re-scan a target on an interval — new '
      + 'entities and correlations accrue as they appear.</p></div>';
  }
  const rows = sessions.map(s=>`<tr>
    <td>${kindPill(s.target&&s.target.kind)} <code>${esc((s.target&&s.target.value)||s.id)}</code>${(s.live_options&&s.live_options.radar)?' <span class="label label-info" title="Radar: paid APIs not re-queried on covered seeds">radar</span>':''}</td>
    <td>${statusPill(s.status)}</td>
    <td class="text-right">${s.iteration||0}${(s.live_options&&s.live_options.iterations)?` / ${s.live_options.iterations}`:''}</td>
    <td class="text-right">${(s.live_options&&s.live_options.interval_secs)||'?'}s</td>
    <td>${esc(fmtDate(s.started_at))}</td>
    <td>${s.last_iteration_at?esc(fmtDate(s.last_iteration_at)):'<span class="text-muted">—</span>'}</td>
    <td class="text-right">${(s.scan_ids||[]).length}</td>
    <td class="text-right">
      <button class="btn btn-info btn-xs" data-livestream="${attr(s.id)}" data-lval="${attr((s.target&&s.target.value)||s.id)}" title="Tail this session's live events"><i class="glyphicon glyphicon-transfer"></i></button>
      <button class="btn btn-danger btn-xs" data-livestop="${attr(s.id)}" title="Stop"><i class="glyphicon glyphicon-stop"></i></button>
    </td>
  </tr>`).join('');
  return `<div class="table-responsive"><table class="table table-condensed table-striped">
    <thead><tr><th>Target</th><th>Status</th><th class="text-right">Iter</th>
      <th class="text-right">Interval</th><th>Started</th><th>Last run</th>
      <th class="text-right">Scans</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}
/* Historical review of past radar sweeps — sourced from the persisted scans
   table (GET /api/v1/radar/history), so it survives a server restart unlike
   the "Active sessions" table above, which only shows what's still held in
   memory. This is the surface that lets an operator reconstruct "what was
   around me" after the fact, even having forgotten the session id. */
export function renderRadarHistory(sweeps){
  if (!sweeps.length){
    return '<div class="empty-state"><h3>No radar sweeps yet</h3>'
      + '<p>Every sweep the radar button or continuous radar ever queued is listed here, newest '
      + 'first, once it runs — reviewable later even after a server restart.</p></div>';
  }
  const rows = sweeps.map(sw=>{
    const seed = sw.target && sw.target.kind==='mac_address' ? 'local network' : 'ambient (GPS/RF)';
    const dur = sw.finished_at && sw.started_at ? (sw.finished_at - sw.started_at) : null;
    return `<tr>
      <td>${esc(fmtDate(sw.started_at))}</td>
      <td>${esc(seed)}</td>
      <td>${statusPill(sw.status)}</td>
      <td class="text-right">${dur==null?'<span class="text-muted">—</span>':(dur+'s')}</td>
      <td class="text-right">${sw.entity_count||0}</td>
      <td><a href="#/scaninfo?id=${attr(sw.id)}" class="btn btn-default btn-xs" title="Review this sweep's signals"><i class="glyphicon glyphicon-eye-open"></i>&nbsp;Review</a></td>
    </tr>`;
  }).join('');
  return `<div class="table-responsive"><table class="table table-condensed table-striped">
    <thead><tr><th>When</th><th>Seed</th><th>Status</th><th class="text-right">Duration</th>
      <th class="text-right">Signals</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}
export async function renderLive(v){
  const data = await API.liveList();
  const sessions = data.sessions || [];
  // A history-fetch hiccup must never take down the whole Live view (the
  // "Active sessions" panel above is the more critical, real-time surface).
  let sweeps = [];
  try { sweeps = (await API.radarHistory(50)).sweeps || []; } catch(_){}
  v.innerHTML = `
    <h2>Live Monitor <small class="text-muted">continuous re-scan of a target on an interval</small>
      <div class="pull-right"><button class="btn btn-default btn-sm" onclick="render()" title="Refresh"><i class="glyphicon glyphicon-refresh"></i></button></div>
    </h2>
    <hr style="margin:8px 0 14px 0">
    <div class="panel panel-default" style="border-color:var(--accent)">
      <div class="panel-heading" style="background:var(--info-dim)"><b><i class="glyphicon glyphicon-record" style="color:var(--accent)"></i>&nbsp;Live Signal Radar</b>
        <span class="text-muted" style="font-weight:400">— continuous autonomous enumeration of <i>this device's</i> passive signals</span></div>
      <div class="panel-body">
        <p class="text-muted" style="margin:0 0 10px 0;font-size:12px">
          Continuously enumerates the signals <b>around the device</b> in real time — Wi-Fi access points, Bluetooth, cell towers,
          the GPS/last-known fix and the local network — using only the on-device passive sensors (<code>signal_radar</code>,
          <code>device_sensors</code>, <code>wifi_intel</code>, <code>cell_intel</code>, <code>local_net</code>). It requires
          <b>no input whatsoever</b>: no target, no seed, no interval — just one tap. It is entirely separate from target seed
          scanning (those sensors run on <i>no other scan</i>), and re-sweeps on a loop so new signals surface as they appear or the
          device moves.
        </p>
        <div class="form-inline">
          <button id="radar-go" class="btn btn-info"><i class="glyphicon glyphicon-record"></i>&nbsp;Activate Live Radar</button>
          <span class="text-muted" style="margin-left:8px;font-style:italic">zero input — one tap starts a continuous passive-signal sweep</span>
          <span id="radar-status" class="text-muted" style="margin-left:10px"></span>
        </div>
      </div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading"><b>Start a live session</b></div>
      <div class="panel-body">
        <form id="live-form" class="form-inline" onsubmit="return false">
          <select id="live-kind" class="form-control input-sm">
            ${TARGET_KINDS.map(k=>`<option value="${attr(k.v)}"${k.v==='auto'?' selected':''}>${esc(k.label)}</option>`).join('')}
          </select>
          <input id="live-value" type="text" class="form-control input-sm" placeholder="target value…" style="min-width:200px" autocomplete="off" autocapitalize="off" spellcheck="false">
          <label class="text-muted" style="font-weight:normal;margin-left:8px">every</label>
          <input id="live-interval" type="number" class="form-control input-sm" value="60" min="1" style="width:80px"> s
          <label class="text-muted" style="font-weight:normal;margin-left:8px">for</label>
          <input id="live-iters" type="number" class="form-control input-sm" placeholder="∞" min="1" style="width:80px"> iterations
          <label class="text-muted" style="font-weight:normal;margin-left:8px" title="Persist the keyed-module ledger across sweeps so paid APIs are never re-queried on a seed already covered — each sweep spends quota only on NEW seeds.">
            <input id="live-radar" type="checkbox" checked>&nbsp;Radar
          </label>
          <button id="live-start" class="btn btn-danger btn-sm" style="margin-left:8px"><i class="glyphicon glyphicon-play"></i>&nbsp;Start</button>
        </form>
        <p class="text-muted" style="margin:8px 0 0 0;font-size:12px"><b>Radar</b> (recommended): each sweep spends API budget only on NEW seeds — a keyed module never re-queries a seed an earlier sweep already covered, so a long-running radar isn't aggressive with the APIs. Unchecked = classic live re-scan (re-queries everything each interval to catch fresh data). Leave iterations blank to run until toggled off; tuned low for Termux battery/data.</p>
      </div>
    </div>
    <div class="panel panel-default" id="live-stream-panel" style="display:none;border-color:var(--info)">
      <div class="panel-heading" style="background:rgba(91,192,222,0.12)">
        <b><i class="glyphicon glyphicon-transfer" style="color:var(--info)"></i>&nbsp;Live activity</b>
        <span id="live-stream-label" class="text-muted" style="font-weight:400"></span>
        <button class="btn btn-default btn-xs pull-right" onclick="closeLiveStream()" title="Stop tailing this session"><i class="glyphicon glyphicon-stop"></i>&nbsp;Stop</button>
        <button class="btn btn-default btn-xs pull-right" style="margin-right:6px" onclick="saveLiveShown()" title="Save the live activity shown here to a .log file"><i class="glyphicon glyphicon-download-alt"></i>&nbsp;Save shown</button>
      </div>
      <div class="panel-body" id="live-stream-host" style="max-height:320px;overflow:auto;padding:6px 10px;font-size:12px">
        <div class="text-muted">Waiting for events…</div>
      </div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading"><b>Active sessions</b> <span class="badge">${sessions.length}</span></div>
      <div id="live-sessions">${renderLiveSessions(sessions)}</div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading"><b><i class="glyphicon glyphicon-time"></i>&nbsp;Radar history</b> <span class="badge">${sweeps.length}</span>
        <span class="text-muted" style="font-weight:400">— review past sweeps later, even after a restart</span></div>
      <div id="radar-history">${renderRadarHistory(sweeps)}</div>
    </div>`;
  $('#live-start').addEventListener('click', async ()=>{
    const kind = $('#live-kind').value;
    const value = (($('#live-value')||{}).value || '').trim();
    if (!value){ if (typeof alertify !== 'undefined') alertify.warning('Enter a target value'); return; }
    const interval_secs = Math.max(1, parseInt(($('#live-interval')||{}).value || '60', 10) || 60);
    const itersRaw = (($('#live-iters')||{}).value || '').trim();
    const live = { interval_secs, radar: !!(($('#live-radar')||{}).checked) };
    if (itersRaw){ const n = parseInt(itersRaw, 10); if (n>=1) live.iterations = n; }
    try {
      // Unified live scan: 'auto' omits `kind` so the server detects it.
      const payload = kind==='auto' ? { value, options: {}, live } : { kind, value, options: {}, live };
      await API.liveCreate(payload);
      if (typeof alertify !== 'undefined') alertify.success('Live session started');
      render();
    } catch(e){ if (typeof alertify !== 'undefined') alertify.error('Start failed: '+e.message); }
  });
  // Live Signal Radar — the single, deliberate button that activates the on-device
  // sensors. Fully autonomous: NO input whatsoever (no target, no seed, no interval).
  // Starts a CONTINUOUS live radar session, server-configured, that re-enumerates the
  // device's passive signals in real time. Re-renders so the new session appears in
  // "Active sessions", where its iteration count climbs live.
  $('#radar-go').addEventListener('click', async ()=>{
    const btn = $('#radar-go'), st = $('#radar-status');
    btn.disabled = true; btn.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>&nbsp;Starting…';
    if (st) st.textContent = 'Activating continuous passive-signal radar…';
    try {
      await API.radarLive();
      toast('Continuous radar started — enumerating passive signals');
      render();
    } catch(e){
      btn.disabled = false; btn.innerHTML = '<i class="glyphicon glyphicon-record"></i>&nbsp;Activate Live Radar';
      if (st) st.textContent = '';
      if (typeof alertify !== 'undefined') alertify.error('Radar failed: '+e.message);
    }
  });
  wireLiveStops();
  wireLiveStreams();
  // Poll the session list while this page is open so iteration counts climb live.
  clearLiveTimer();
  S.liveTimer = setInterval(async ()=>{
    try {
      const d = await API.liveList();
      const sessions = d.sessions || [];
      const host = $('#live-sessions');
      if (host){ host.innerHTML = renderLiveSessions(sessions); wireLiveStops(); wireLiveStreams(); }
      // If the session being tailed has ended (gone from the list), close its
      // stream so the Live-activity panel doesn't hang on a dead session.
      if (S.streamLiveId && !sessions.some(s=>s.id===S.streamLiveId)) closeLiveStream();
    } catch(_){}
  }, 8000);
}

