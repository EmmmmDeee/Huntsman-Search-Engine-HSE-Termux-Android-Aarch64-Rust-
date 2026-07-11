import { API } from '/static/js/api.js';
import { $, attr, esc, extLink, fmtDate, kindPill } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';

/* ═══════════ Page: DIFF (#/diff?a=X&b=Y) — temporal scan comparison ═══════════ */
export async function renderDiff(v){
  const data = await API.scans();
  const scans = (data.scans||[]).filter(s=>s.status==='complete'||s.status==='aborted');
  let {a, b} = S.route.params;
  // Default the picker to the two most recent scans of the SAME subject, so the
  // common case (re-scan drift) is one click away.
  if (!a && !b && scans.length>=2){
    const bySubject = {};
    scans.forEach(s=>{ const k=(s.target?.value||'')+'|'+(s.target?.kind||''); (bySubject[k]||(bySubject[k]=[])).push(s); });
    const pair = Object.values(bySubject).find(g=>g.length>=2);
    if (pair){ b = pair[0].id; a = pair[1].id; }
  }
  const opt = (sel)=>scans.map(s=>`<option value="${attr(s.id)}"${s.id===sel?' selected':''}>${esc(s.target?.value||s.id)} — ${esc(fmtDate(s.started_at))} (${s.entity_count||0})</option>`).join('');
  v.innerHTML = `
    <div class="crumbs"><a href="#/scans">Scans</a> &raquo; Compare</div>
    <h2>Compare Scans <small class="text-muted">temporal diff — what changed between two runs</small></h2>
    <hr style="margin:8px 0 14px 0">
    ${scans.length<2 ? `<div class="empty-state"><h3>Need at least two finished scans</h3>
       <p>Run a subject twice (or <a href="#/newscan">rescan</a> an existing one) to see what drifted between runs.</p></div>` : `
    <div class="row" style="margin-bottom:12px">
      <div class="col-sm-5"><label class="text-muted" style="font-size:11px">BASELINE (earlier)</label>
        <select id="d-a" class="form-control input-sm">${opt(a)}</select></div>
      <div class="col-sm-5"><label class="text-muted" style="font-size:11px">LATER</label>
        <select id="d-b" class="form-control input-sm">${opt(b)}</select></div>
      <div class="col-sm-2" style="padding-top:18px">
        <button id="d-go" class="btn btn-primary btn-sm btn-block"><i class="glyphicon glyphicon-transfer"></i>&nbsp;Compare</button></div>
    </div>
    <div id="diff-body"></div>`}
  `;
  if (scans.length<2) return;
  const run = async()=>{
    const av = $('#d-a').value, bv = $('#d-b').value;
    const host = $('#diff-body');
    if (av===bv){ host.innerHTML = '<div class="alert alert-warning">Pick two different scans.</div>'; return; }
    nav(`#/diff?a=${encodeURIComponent(av)}&b=${encodeURIComponent(bv)}`); // shareable URL
    host.innerHTML = '<p class="text-muted">Computing diff…</p>';
    try {
      const d = await API.diff(av, bv);
      host.innerHTML = renderDiffResult(d);
    } catch(e){ host.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
  };
  $('#d-go').addEventListener('click', run);
  if (a && b) run();
}
export function diffRow(e){
  return `<tr><td>${kindPill(e.kind)}</td><td style="word-break:break-word"><code>${extLink(e.value)}</code></td>
    <td class="text-right"><code>${(e.c_effective!=null?Number(e.c_effective):0).toFixed(3)}</code></td></tr>`;
}
export function renderDiffResult(d){
  const added = d.added||[], removed = d.removed||[], shifts = d.confidence_shifts||[];
  if (!added.length && !removed.length && !shifts.length){
    return `<div class="empty-state"><h3>Identical</h3><p>The two scans found the same entities at the same confidence — ${d.common||0} in common.</p></div>`;
  }
  const tbl = (title, color, rows, mk) => rows.length ? `
    <div class="panel panel-default"><div class="panel-heading" style="font-weight:600;color:${color}">${title} <span class="badge">${rows.length}</span></div>
      <div class="table-responsive"><table class="table table-condensed table-striped">
        <thead><tr><th>Type</th><th>Value</th><th class="text-right">${title==='Re-scored'?'Before → After':'C_eff'}</th></tr></thead>
        <tbody>${rows.map(mk).join('')}</tbody></table></div></div>` : '';
  const shiftRow = s=>`<tr><td>${kindPill(s.kind)}</td><td style="word-break:break-word"><code>${extLink(s.value)}</code></td>
    <td class="text-right"><code>${Number(s.before).toFixed(3)} → ${Number(s.after).toFixed(3)}</code>
      <span style="color:${s.after>=s.before?'#3c763d':'#a94442'}">${s.after>=s.before?'▲':'▼'}</span></td></tr>`;
  return `<div class="row" style="margin-bottom:10px">
      <div class="col-xs-4"><div class="stat-card"><div class="lab">Added</div><div class="val" style="color:#3c763d">+${added.length}</div></div></div>
      <div class="col-xs-4"><div class="stat-card"><div class="lab">Removed</div><div class="val" style="color:#a94442">−${removed.length}</div></div></div>
      <div class="col-xs-4"><div class="stat-card"><div class="lab">In common</div><div class="val">${d.common||0}</div></div></div>
    </div>
    ${tbl('Added','#3c763d',added,diffRow)}
    ${tbl('Removed','#a94442',removed,diffRow)}
    ${tbl('Re-scored','#8a6d3b',shifts,shiftRow)}`;
}

