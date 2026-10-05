import { API } from '/static/js/api.js';
import { $, attr, esc, fmtDate } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';
import { renderDiffResultHtml, scanLabel, scanState } from '/static/hse_wasm_ui.js';

/* ═══════════ Page: DIFF (#/diff?a=X&b=Y) — temporal scan comparison ═══════════ */
export async function renderDiff(v){
  const data = await API.scans();
  // Finished scans. Aborted and interrupted ones stopped early and are marked
  // as such, since a diff against one also shows what it never reached.
  const scans = (data.scans||[]).filter(s=>['complete','aborted','interrupted'].includes(scanState(s)));
  let {a, b} = S.route.params;
  // Default the picker to the two most recent scans of the SAME subject, so the
  // common case (re-scan drift) is one click away.
  // Two COMPLETE scans when a subject has them: a diff against one that
  // stopped early also lists everything it never reached as "removed".
  if (!a && !b && scans.length>=2){
    const pairOf = list=>{
      const bySubject = {};
      list.forEach(s=>{ const k=(s.target?.value||'')+'|'+(s.target?.kind||''); (bySubject[k]||(bySubject[k]=[])).push(s); });
      return Object.values(bySubject).find(g=>g.length>=2);
    };
    const pair = pairOf(scans.filter(s=>scanState(s)==='complete')) || pairOf(scans);
    if (pair){ b = pair[0].id; a = pair[1].id; }
  }
  // A scan is called by its name, and a named scan shows what it scanned.
  const label = (s)=>{ const l = scanLabel(s); return l.target ? `${l.title} · ${l.target}` : l.title; };
  const opt = (sel)=>scans.map(s=>`<option value="${attr(s.id)}"${s.id===sel?' selected':''}>${esc(label(s))} — ${esc(fmtDate(s.started_at))} (${s.entity_count||0}${scanState(s)==='complete'?'':` · ${esc(scanState(s))}`})</option>`).join('');
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
      host.innerHTML = renderDiffResultHtml(d);
    } catch(e){ host.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
  };
  $('#d-go').addEventListener('click', run);
  if (a && b) run();
}

