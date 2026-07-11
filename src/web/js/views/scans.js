import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtDate, fmtDuration, kindPill, nowSec, statusPill, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';
import { render } from '/static/js/main.js';

/* ═══════════ Page: SCANLIST (#/scans) ═══════════ */
export async function renderScans(v){
  const data = await API.scans();
  S.scans = data.scans || [];
  const stats = scanStats(S.scans);

  v.innerHTML = `
    <h2>Scans &nbsp;<small class="text-muted">${stats.total} scan${stats.total===1?'':'s'} on record</small>
        <div class="pull-right">
          <button class="btn btn-default btn-sm" onclick="render()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
          <a class="btn btn-default btn-sm" href="#/diff" title="Compare two scans of the same subject over time"><i class="glyphicon glyphicon-transfer"></i>&nbsp;Compare</a>
          <a class="btn btn-danger btn-sm" href="#/newscan"><i class="glyphicon glyphicon-plus"></i>&nbsp;New Scan</a>
        </div>
    </h2>
    <hr style="margin:8px 0 14px 0">

    <div class="row">
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Total</div><div class="val">${stats.total}</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Running</div><div class="val" style="color:${stats.running?'#31708f':'#888'}">${stats.running}</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Complete</div><div class="val" style="color:${stats.complete?'#3c763d':'#888'}">${stats.complete}</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Entities found</div><div class="val">${stats.entities}</div></div></div>
    </div>

    <div class="panel panel-default" id="scanlist">
      <div class="panel-heading">
        Recent scans
        <input id="scan-filter" type="search" class="form-control input-sm pull-right"
               style="width:240px;margin-top:-4px" placeholder="Filter scans…">
      </div>
      <div id="scans-table-host">${renderScansTable(S.scans)}</div>
    </div>
  `;
  if (S.scans.length){ wireScansTable(); }
  const f = $('#scan-filter');
  if (f) f.addEventListener('input', ()=>{
    const q = f.value.trim().toLowerCase();
    const rows = q ? S.scans.filter(s =>
      (s.target?.value||'').toLowerCase().includes(q)
      || (s.target?.kind||'').includes(q)
      || (s.status||'').includes(q)
      || (s.id||'').includes(q)
    ) : S.scans;
    $('#scans-table-host').innerHTML = renderScansTable(rows);
    wireScansTable();
  });
}
/* Daily API-quota dashboard from GET /api/v1/stats. Surfaces session
   consumption for the budget-bounded paid providers (SeekNow / OathNet /
   WiGLE) so the operator can see "maximum API effectiveness" at a glance, and
   — critically — the WiGLE account email-verification flag: an unverified
   WiGLE account silently fails every database query, so we flag it loudly. */
export function budgetBar(b){
  if(!b) return '<span class="text-muted">n/a</span>';
  const used=b.session_used||0, cap=b.session_cap||0;
  const pct = cap>0 ? Math.min(100, Math.round(used*100/cap)) : 0;
  const col = b.quota_exhausted ? '#a94442' : (pct>=80?'#8a6d3b':'#3c763d');
  const lab = cap>0 ? `${used} / ${cap}` : `${used}`;
  return `<div style="display:flex;align-items:center;gap:6px">
    <div style="flex:1;background:var(--bg-elevated-2);border-radius:3px;height:8px;overflow:hidden">
      <div style="width:${pct}%;height:100%;background:${col}"></div></div>
    <span class="text-muted" style="font-size:11px;min-width:64px;text-align:right">${esc(lab)}${b.quota_exhausted?' <b style="color:var(--danger)">FULL</b>':''}</span>
  </div>`;
}
export function apiBudgetsPanel(s){
  const w = s.wigle||{}, acct = w.account||{};
  // verified === false is the silent-failure case; null = not yet polled.
  const verBadge = acct.verified===false
    ? '<span class="label label-danger" title="Email-verification not confirmed — WiGLE database queries will fail until the account email is verified at wigle.net">account UNVERIFIED</span>'
    : acct.verified===true
      ? '<span class="label label-success">account verified</span>'
      : '<span class="label label-default" title="Not yet polled this session">account status unknown</span>';
  const rows = [
    ['SeekNow', budgetBar(s.seeknow)],
    ['OathNet', budgetBar(s.oathnet)],
    ['WiGLE · WiFi geo', budgetBar(w.geo)],
    ['WiGLE · BSSID', budgetBar(w.bssid)],
    ['WiGLE · cell', budgetBar(w.cell)],
    ['WiGLE · bluetooth', budgetBar(w.bluetooth)],
  ];
  return `<div class="panel panel-default" style="margin-top:12px">
    <div class="panel-heading"><b>API Budgets</b>
      <span class="pull-right" style="font-size:12px">WiGLE ${verBadge}</span></div>
    <div class="panel-body">
      <table class="table table-condensed" style="margin-bottom:0">
        ${rows.map(([k,v])=>`<tr><td style="width:160px;white-space:nowrap">${k}</td><td>${v}</td></tr>`).join('')}
      </table>
      <p class="text-muted" style="margin:8px 0 0;font-size:11px">Session quota consumed so far. Paid GEOINT (WiGLE) is gated to fire only after the free geo layer corroborates a coordinate through recursion (≥2 sources), so the daily allowance is spent confirming the subject's real location, not chasing noise.</p>
    </div>
  </div>`;
}
export function scanStats(scans){
  let running=0,complete=0,failed=0,entities=0;
  for(const s of scans){
    if (s.status==='running'||s.status==='pending') running++;
    else if (s.status==='complete') complete++;
    else if (s.status==='failed') failed++;
    entities += s.entity_count||0;
  }
  return {total:scans.length,running,complete,failed,entities};
}
export function renderScansTable(scans){
  if (!scans.length){
    return `<div class="empty-state"><h3>No scans yet</h3>
            <p>Submit a target to start the first scan. Results stream in real-time
               and are persisted to the local database.</p>
            <a class="btn btn-danger" href="#/newscan"><i class="glyphicon glyphicon-plus"></i>&nbsp;Run Scan Now</a></div>`;
  }
  const rows = scans.map(s=>{
    const kind = s.target?.kind||'—';
    const dur = s.finished_at && s.started_at ? s.finished_at - s.started_at
              : s.status==='running' ? nowSec()-(s.started_at||nowSec()) : null;
    return `<tr>
      <td><a href="#/scaninfo?id=${attr(s.id)}" class="link">${esc(s.target?.value||s.id)}</a></td>
      <td>${kindPill(kind)}</td>
      <td>${esc(fmtDate(s.started_at))}</td>
      <td>${esc(fmtDuration(dur))}</td>
      <td>${statusPill(s.status)}</td>
      <td class="text-right">${s.entity_count||0}</td>
      <td>
        <a href="#/scaninfo?id=${attr(s.id)}" class="btn btn-default btn-xs" title="Open"><i class="glyphicon glyphicon-eye-open"></i></a>
        ${(s.status==='running'||s.status==='pending')
          ? `<button class="btn btn-warning btn-xs" data-cancel="${attr(s.id)}" title="Stop scan"><i class="glyphicon glyphicon-stop"></i></button>`
          : `<button class="btn btn-default btn-xs" data-rerun="${attr(s.id)}" title="Rescan"><i class="glyphicon glyphicon-repeat"></i></button>`}
        <a class="btn btn-default btn-xs" href="${API.csvUrl(s.id)}" title="Export CSV"><i class="glyphicon glyphicon-download-alt"></i></a>
        <button class="btn btn-danger btn-xs" data-delete="${attr(s.id)}" title="Delete"><i class="glyphicon glyphicon-trash"></i></button>
      </td>
    </tr>`;
  }).join('');
  return `<div class="table-responsive"><table class="table table-striped table-condensed tablesorter" id="scans-table">
    <thead><tr>
      <th>Target</th><th>Type</th><th>Created</th><th>Duration</th>
      <th>Status</th><th class="text-right">Entities</th>
      <th class="sorter-false">Actions</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}
export function wireScansTable(){
  if (window.jQuery && jQuery.fn.tablesorter) {
    try { jQuery('#scans-table').tablesorter({sortList:[[2,1]]}); } catch {}
  }
  $$('button[data-rerun]').forEach(b=>b.addEventListener('click', e=>{
    e.stopPropagation();
    const id = b.dataset.rerun;
    alertify.confirm('Re-run scan', 'Start a new scan with the same target and options?', async ()=>{
      try { const r = await API.rerun(id); toast('Scan queued'); nav(`#/scaninfo?id=${r.scan_id}&tab=log`); }
      catch(e){ toast(e.message,'err'); }
    }, ()=>{});
  }));
  $$('button[data-cancel]').forEach(b=>b.addEventListener('click', e=>{
    e.stopPropagation();
    const id = b.dataset.cancel;
    // Stop an in-flight scan straight from the list (SpiderFoot parity). The
    // engine sees the cancel flag at its next gate, lets in-flight modules
    // finish, and marks the scan `aborted`; partial results are kept.
    alertify.confirm('Stop scan', 'Stop the scan now? Modules already in flight will complete, then no further work will run. Results produced so far are kept.', async ()=>{
      try { await API.cancel(id); toast('Stop requested'); setTimeout(render, 1500); }
      catch(e){ toast(e.message,'err'); }
    }, ()=>{});
  }));
  $$('button[data-delete]').forEach(b=>b.addEventListener('click', e=>{
    e.stopPropagation();
    const id = b.dataset.delete;
    alertify.confirm('Delete scan', 'This deletes the scan, its correlations, and any entities not shared with another scan. Continue?', async ()=>{
      try { await API.remove(id); toast('Scan deleted'); render(); }
      catch(e){ toast(e.message,'err'); }
    }, ()=>{});
  }));
}

