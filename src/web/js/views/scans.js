import { API } from '/static/js/api.js';
import { $, $$, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';
import { render } from '/static/js/main.js';
import { renderScansTableHtml, scanIsActive, scanMatches, scanState } from '/static/hse_wasm_ui.js';

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
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Complete</div><div class="val" style="color:${stats.complete?'#3c763d':'#888'}">${stats.complete}</div>${stats.partial||stats.aborted||stats.failed||stats.interrupted?`<div class="text-muted" style="font-size:10px">${[stats.partial?`${stats.partial} partial`:'',stats.aborted?`${stats.aborted} aborted`:'',stats.failed?`${stats.failed} failed`:'',stats.interrupted?`${stats.interrupted} interrupted`:''].filter(Boolean).join(' · ')}</div>`:''}</div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Entities found</div><div class="val">${stats.entities}</div></div></div>
    </div>

    <div class="panel panel-default" id="scanlist">
      <div class="panel-heading">
        Recent scans
        <input id="scan-filter" type="search" class="form-control input-sm pull-right"
               style="width:240px;margin-top:-4px" placeholder="Filter scans…">
      </div>
      <div id="scans-table-host">${renderScansTableHtml(S.scans)}</div>
    </div>
  `;
  if (S.scans.length){ wireScansTable(); }
  const f = $('#scan-filter');
  if (f) f.addEventListener('input', ()=>{
    // wasm-ui's scanMatches: name, target, kind, shown state or id.
    const rows = S.scans.filter(s => scanMatches(s, f.value));
    $('#scans-table-host').innerHTML = renderScansTableHtml(rows);
    wireScansTable();
  });
}
export function scanStats(scans){
  let running=0,complete=0,partial=0,aborted=0,failed=0,interrupted=0,entities=0;
  for(const s of scans){
    // The display state, not the persisted status: a scan whose server died
    // reads `running` in the store and is not running (REQ-SCANSTATUS-038).
    const st = scanState(s);
    if (scanIsActive(s)) running++;
    // A `complete` row whose finalise fell short (`finalise_incomplete`,
    // REQ-SCANSTATUS-030) is the `partial` its row pill says, not a green
    // complete one; an aborted one stays with the aborted (REQ-SCANSTATUS-032).
    else if (st==='complete' && s.finalise_incomplete===true) partial++;
    else if (st==='complete') complete++;
    // `aborted` is a distinct terminal state (operator-stopped, data kept) —
    // without its own bucket it matched no branch and vanished from the tallies
    // while still inflating `total`. `failed` was counted but never rendered.
    else if (st==='aborted') aborted++;
    else if (st==='failed') failed++;
    else if (st==='interrupted') interrupted++;
    entities += s.entity_count||0;
  }
  return {total:scans.length,running,complete,partial,aborted,failed,interrupted,entities};
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
