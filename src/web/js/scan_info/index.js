import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtDate, fmtDuration, kindPill, kindToStr, nowSec, statusPill, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { renderBrowse } from '/static/js/scan_info/browse.js';
import { renderCorrelations } from '/static/js/scan_info/correlations.js';
import { renderGraph } from '/static/js/scan_info/graph.js';
import { renderInsights } from '/static/js/scan_info/insights.js';
import { renderLog } from '/static/js/scan_info/log.js';
import { renderSummary } from '/static/js/scan_info/report.js';
import { renderStealer } from '/static/js/scan_info/stealer.js';
import { S } from '/static/js/state.js';
import { clearScanTimer, pageHidden } from '/static/js/timers.js';
import { render } from '/static/js/main.js';

/* ═══════════ Page: SCANINFO (#/scaninfo?id=X[&tab=Y]) ═══════════ */
export async function renderScanInfo(v){
  const {id, tab} = S.route.params;
  // Streamlined tab set. Legacy/deep-link values fold onto it: 'report' and any
  // unknown value → Summary; 'network' also → Summary but scrolls to its
  // section (which now lives there).
  const activeTab = (!tab || tab === 'report' || tab === 'network') ? 'summary' : tab;
  // Only the scan itself is required; correlations/relations can 500 on a
  // legacy scan, so one failing sub-resource must not blank the whole page.
  //
  // relations is fetched ONLY for the Graph tab — it is the sole consumer
  // (browse/correlations/report/insights/stealer/log all read S.entities
  // and/or S.correlations, never S.relations). Every other tab paid for a
  // full relations round-trip it never used, on EVERY render — including
  // this page's own 8s live-refresh while a scan runs (scanRefreshTick,
  // below), so a Summary or Browse tab left open during a scan repeated
  // that wasted fetch roughly 450 times an hour. Skipped rather than fetched
  // and discarded: `Promise.resolve` needs no network round-trip at all, so
  // this is a real elision, not a relabelled one.
  const wantRelations = activeTab === 'graph';
  const [scanR, entsR, corrsR, relsR] = await Promise.allSettled([
    API.scan(id),
    API.entities(id),
    API.correlations(id),
    wantRelations ? API.relations(id) : Promise.resolve({ relations: [] }),
  ]);
  if (scanR.status !== 'fulfilled') throw scanR.reason;
  const scan = scanR.value;
  S.scan = scan;
  S.entities     = entsR.status ==='fulfilled' ? (entsR.value.entities||[])      : [];
  S.correlations = corrsR.status==='fulfilled' ? (corrsR.value.correlations||[]) : [];
  S.relations    = relsR.status ==='fulfilled' ? (relsR.value.relations||[])     : [];
  // The /entities endpoint paginates (default limit 1000). Capture the query's
  // true match total from the envelope so Browse can disclose when the loaded
  // slice is only part of the scan, instead of silently reporting the fetched
  // count as if it were the whole set.
  S.entitiesTotal = entsR.status==='fulfilled' ? (entsR.value.total ?? S.entities.length) : 0;
  // `EntityKind::Other(s)` serializes as the object {"other":"…"} (externally
  // tagged), unlike every unit variant which is a plain string. Left as-is it
  // renders as "[object Object]" and, because it's used as a Map key, splits
  // into one bogus row per entity. Normalise every kind to a flat string once,
  // here, so all downstream views (pills, type grouping, relations) are correct.
  S.entities.forEach(e=>{ e.kind = kindToStr(e.kind); });

  const dur = scan.finished_at && scan.started_at ? scan.finished_at - scan.started_at
            : scan.status==='running' ? nowSec() - (scan.started_at||nowSec()) : null;

  v.innerHTML = `
    <div class="crumbs"><a href="#/scans">Scans</a> &raquo; ${esc(scan.target?.value||id)}</div>
    <h2>${esc(scan.target?.value||id)}
        <small class="text-muted" style="margin-left:6px">${kindPill(scan.target?.kind)} ${statusPill(scan.status)}</small>
        <div class="pull-right">
          <button class="btn btn-default btn-sm" onclick="render()" title="Refresh"><i class="glyphicon glyphicon-refresh"></i></button>
          ${(scan.status==='running'||scan.status==='pending')
            ? `<button class="btn btn-warning btn-sm" data-cancel="${attr(id)}" title="Abort scan"><i class="glyphicon glyphicon-stop"></i>&nbsp;Abort</button>`
            : ''}
          <button class="btn btn-default btn-sm" data-rerun="${attr(id)}" title="Rescan"><i class="glyphicon glyphicon-repeat"></i>&nbsp;Rescan</button>
          <a class="btn btn-default btn-sm" href="${API.csvUrl(id)}" data-download title="Export entities as CSV"><i class="glyphicon glyphicon-download-alt"></i>&nbsp;CSV</a>
          <a class="btn btn-default btn-sm" id="si-json-link" href="${API.reportUrl(id, false)}" data-download title="Export full report as JSON"><i class="glyphicon glyphicon-save"></i>&nbsp;JSON</a>
          <a class="btn btn-default btn-sm" href="${API.gexfUrl(id)}" data-download title="Export the entity graph as GEXF (open in Gephi / any graph tool)"><i class="glyphicon glyphicon-share-alt"></i>&nbsp;GEXF</a>
          <a class="btn btn-default btn-sm" href="${API.eventsLogUrl(id)}" download data-download title="Download the scan event log (.log) — client-safe: your breach-source providers (SeekNow, OathNet, …) are shown as ‘breach-source’, never named"><i class="glyphicon glyphicon-download"></i>&nbsp;Log</a>
          <a class="btn btn-warning btn-sm" href="${API.debugUrl(id)}" download data-download title="⚠ OPERATOR ONLY — the full debug bundle NAMES your breach-source providers (SeekNow, OathNet, …). For your own debugging; do NOT share it with a client."><i class="glyphicon glyphicon-list-alt"></i>&nbsp;Debug bundle (operator)</a>
          <button class="btn btn-danger btn-sm" data-delete="${attr(id)}" title="Delete"><i class="glyphicon glyphicon-trash"></i></button>
        </div>
        <div class="text-muted" style="font-size:11px;margin-top:4px">
          <label style="font-weight:normal;cursor:pointer">
            <input type="checkbox" id="si-include-infra"> Include infrastructure entities (cloud buckets, CDN IPs, tracking IDs) in the JSON report
          </label>
          <div style="margin-top:2px"><i class="glyphicon glyphicon-lock"></i>&nbsp;CSV / JSON / GEXF / Log downloads are <b>client-safe</b> — your breach-source providers are shown as “breach-source”, never named. Only the <span class="text-warning">Debug bundle (operator)</span> names them.</div>
        </div>
    </h2>
    <hr style="margin:8px 0 14px 0">

    <div class="row">
      <div class="col-sm-3 col-xs-6"><div class="stat-card"><div class="lab">Entities</div><div class="val">${scan.entity_count || S.entities.length}</div></div></div>
      <div class="col-sm-3 col-xs-6"><div class="stat-card"><div class="lab">Correlations</div><div class="val" style="color:${S.correlations.length?'#9b1f9b':'#888'}">${S.correlations.length}</div></div></div>
      <div class="col-sm-3 col-xs-6"><div class="stat-card"><div class="lab">Started</div><div class="val dim">${esc(fmtDate(scan.started_at))}</div></div></div>
      <div class="col-sm-3 col-xs-6"><div class="stat-card"><div class="lab">Duration</div><div class="val dim">${esc(fmtDuration(dur))}</div></div></div>
    </div>

    <ul class="nav nav-tabs">
      ${subTab('summary', 'Summary',      null,                       activeTab)}
      ${subTab('browse',  'Browse',       S.entities.length,          activeTab)}
      ${subTab('graph',   'Graph',        null,                       activeTab)}
      ${subTab('corr',    'Correlations', S.correlations.length||null, activeTab)}
      ${subTab('insights','Insights',     null,                       activeTab)}
      ${subTab('stealer', 'Stealer Logs', null,                       activeTab)}
      ${subTab('log',     'Scan Log',     null,                       activeTab)}
    </ul>
    <div id="scan-body" style="padding-top:14px"></div>
  `;
  // JSON report only: cloud buckets / CDN IPs / tracking IDs are excluded by
  // default (matches `hse export --format report`'s own default); CSV, GEXF,
  // the debug bundle, and Browse never filter them, so only this one link
  // needs the toggle.
  $('#si-include-infra').addEventListener('change', e=>{
    $('#si-json-link').href = API.reportUrl(id, e.target.checked);
  });
  $$('button[data-rerun]').forEach(b=>b.addEventListener('click',()=>{
    alertify.confirm('Re-run scan','Start a new scan with the same target and options?', async()=>{
      try{ const r = await API.rerun(b.dataset.rerun); toast('Scan queued'); nav(`#/scaninfo?id=${r.scan_id}&tab=log`); }
      catch(e){ alertify.error(e.message); }
    }, ()=>{});
  }));
  $$('button[data-delete]').forEach(b=>b.addEventListener('click',()=>{
    alertify.confirm('Delete scan','This deletes the scan, its correlations, and orphan entities. Continue?', async()=>{
      try{ await API.remove(b.dataset.delete); toast('Scan deleted'); nav('#/scans'); }
      catch(e){ alertify.error(e.message); }
    }, ()=>{});
  }));
  // Abort flips the cancel flag for an in-flight scan (issue #23).
  // The engine sees it at its next per-module / per-target gate, lets
  // in-flight modules finish naturally, and marks the scan `aborted`
  // instead of `complete`. Confirm because partial results are kept
  // but no more modules will run.
  $$('button[data-cancel]').forEach(b=>b.addEventListener('click',()=>{
    alertify.confirm('Abort scan','Stop the scan now? Modules already in flight will complete, then no further work will run. Entities + correlations produced so far are kept.', async()=>{
      try{
        await API.cancel(b.dataset.cancel);
        toast('Cancellation requested');
        // Re-render in ~2 s so the status pill updates to "aborted".
        setTimeout(render, 2000);
      } catch(e){ alertify.error(e.message); }
    }, ()=>{});
  }));
  $$('.nav-tabs a[data-sub]').forEach(a=>a.addEventListener('click', e=>{
    e.preventDefault(); nav(`#/scaninfo?id=${id}&tab=${a.dataset.sub}`);
  }));

  const body = $('#scan-body');
  if (activeTab==='browse')        renderBrowse(body);
  else if (activeTab==='corr')     renderCorrelations(body);
  else if (activeTab==='insights') renderInsights(body, id, S.route.query.sub);
  else if (activeTab==='stealer')  renderStealer(body, id);
  else if (activeTab==='graph')    renderGraph(body);
  else if (activeTab==='log')      renderLog(body, scan);
  else {
    // 'summary' (also legacy 'report'/'network' and any unknown tab). The
    // network section lives here now, so a &tab=network deep link scrolls to it.
    renderSummary(body, id, scan);
    if (tab==='network') $('#sum-network')?.scrollIntoView({behavior:'smooth', block:'start'});
  }

  // SpiderFoot-style live refresh: while the scan is still running, re-pull and
  // re-render every 8s so entity/correlation counts and duration climb on their
  // own. The Log tab is excluded — it owns a live SSE stream a re-render would
  // tear down. Re-render re-arms the timer; it stops once status != running.
  clearScanTimer();
  if ((scan.status === 'running' || scan.status === 'pending') && activeTab !== 'log'){
    S.scanTimer = setTimeout(scanRefreshTick, SCAN_REFRESH_MS);
  }
}

const SCAN_REFRESH_MS = 8000;

/* One tick of the running-scan auto-refresh.
 *
 * The refresh is not cheap: `renderScanInfo` re-pulls the scan, its FULL entity
 * set, every correlation and every relation (four requests), then rebuilds the
 * whole view — which on the Graph tab means laying the graph out again from
 * scratch. That is affordable while someone is watching it and pointless when
 * nobody is: a scan-info tab left open in the background on a phone kept doing
 * all of it every 8 seconds for the entire length of the scan, competing for
 * memory with the `hse serve` process running on the same device.
 *
 * So skip the work — but keep the schedule — whenever the page is hidden. The
 * tick still fires and re-arms (a bare timer wakeup costs nothing, and mobile
 * browsers throttle background timers further on their own), so returning to
 * the tab picks the refresh back up within one interval with no listener to
 * register, and therefore none to leak across the many renders this function
 * schedules. Nothing is lost: the next visible tick re-pulls current state, and
 * every count it shows is derived, never accumulated.
 *
 * See `pageHidden` for why the schedule is kept rather than torn down. */
function scanRefreshTick(){
  if (S.route.name !== 'scaninfo') return;
  if (pageHidden()){
    S.scanTimer = setTimeout(scanRefreshTick, SCAN_REFRESH_MS);
    return;
  }
  render();
}
export function subTab(name, label, count, active){
  return `<li class="${active===name?'active':''}"><a href="#" data-sub="${attr(name)}">
    ${esc(label)}${count!=null?` <span class="badge">${count}</span>`:''}
  </a></li>`;
}

