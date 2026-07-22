import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtDate, fmtDuration, kindPill, kindToStr, nowSec, statusPill, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { renderBrowse } from '/static/js/scan_info/browse.js';
import { renderGraph } from '/static/js/scan_info/graph.js';
import { renderLog } from '/static/js/scan_info/log.js';
import { renderReport } from '/static/js/scan_info/report.js';
import { renderStealer } from '/static/js/scan_info/stealer.js';
import { S } from '/static/js/state.js';
import { clearScanTimer } from '/static/js/timers.js';
import { render } from '/static/js/main.js';

/* ═══════════ Page: SCANINFO (#/scaninfo?id=X[&tab=Y]) ═══════════ */
export async function renderScanInfo(v){
  const {id, tab} = S.route.params;
  // Only the scan itself is required; correlations/relations can 500 on a
  // legacy scan, so one failing sub-resource must not blank the whole page.
  const [scanR, entsR, corrsR, relsR] = await Promise.allSettled([
    API.scan(id), API.entities(id), API.correlations(id), API.relations(id)
  ]);
  if (scanR.status !== 'fulfilled') throw scanR.reason;
  const scan = scanR.value;
  S.scan = scan;
  S.entities     = entsR.status ==='fulfilled' ? (entsR.value.entities||[])      : [];
  S.correlations = corrsR.status==='fulfilled' ? (corrsR.value.correlations||[]) : [];
  S.relations    = relsR.status ==='fulfilled' ? (relsR.value.relations||[])     : [];
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
          <a class="btn btn-primary btn-sm" href="${API.debugUrl(id)}" download data-download title="One-click debug bundle: every entity, the full event sequence, correlations, and the scored self-audit with every weakness — one file for complete offline debugging"><i class="glyphicon glyphicon-list-alt"></i>&nbsp;Debug bundle</a>
          <button class="btn btn-danger btn-sm" data-delete="${attr(id)}" title="Delete"><i class="glyphicon glyphicon-trash"></i></button>
        </div>
        <div class="text-muted" style="font-size:11px;margin-top:4px">
          <label style="font-weight:normal;cursor:pointer">
            <input type="checkbox" id="si-include-infra"> Include infrastructure entities (cloud buckets, CDN IPs, tracking IDs) in the JSON report
          </label>
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
      ${subTab('report',  'Report',       null,              tab)}
      ${subTab('browse',  'Browse',       S.entities.length, tab)}
      ${subTab('stealer', 'Stealer Logs', null,              tab)}
      ${subTab('graph',   'Graph',        null,              tab)}
      ${subTab('log',     'Scan Log',     null,              tab)}
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
  if (tab==='browse')        renderBrowse(body);
  else if (tab==='stealer')  renderStealer(body, id);
  else if (tab==='graph')    renderGraph(body);
  else if (tab==='log')      renderLog(body, scan);
  else {
    // 'corr'/'network' (and any other unrecognised tab) fall through to the
    // consolidated Report view, which already contains both sections — just
    // scroll straight to the relevant one instead of leaving the link inert.
    renderReport(body, id, scan);
    if (tab==='corr')         $('#rpt-corr')?.scrollIntoView({behavior:'smooth', block:'start'});
    else if (tab==='network') $('#rpt-network')?.scrollIntoView({behavior:'smooth', block:'start'});
  }

  // SpiderFoot-style live refresh: while the scan is still running, re-pull and
  // re-render every 8s so entity/correlation counts and duration climb on their
  // own. The Log tab is excluded — it owns a live SSE stream a re-render would
  // tear down. Re-render re-arms the timer; it stops once status != running.
  clearScanTimer();
  if ((scan.status === 'running' || scan.status === 'pending') && tab !== 'log'){
    S.scanTimer = setTimeout(()=>{ if (S.route.name === 'scaninfo') render(); }, 8000);
  }
}
export function subTab(name, label, count, active){
  return `<li class="${active===name?'active':''}"><a href="#" data-sub="${attr(name)}">
    ${esc(label)}${count!=null?` <span class="badge">${count}</span>`:''}
  </a></li>`;
}

