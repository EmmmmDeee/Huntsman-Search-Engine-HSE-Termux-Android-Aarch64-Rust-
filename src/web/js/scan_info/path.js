import { API } from '/static/js/api.js';
import { $, esc, kindPill } from '/static/js/helpers.js';

/* ── Connection-path tool — link analysis between two named entities. Enter two
   discovered values and find the shortest relationship chain linking them (plus
   alternative routes). GET /scans/{id}/path. The deeper the scan recursed, the more
   of the graph there is to connect across. ── */
export async function renderPathTool(host, id){
  host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-share-alt"></i>&nbsp;Connection path</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:8px">Find how two discovered entities are linked through the relationship graph — the shortest chain plus alternative routes.</p>
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
      <input id="path-from" class="form-control" style="flex:1;min-width:140px" placeholder="From — e.g. Kyle Diegmann">
      <span class="text-muted">→</span>
      <input id="path-to" class="form-control" style="flex:1;min-width:140px" placeholder="To — e.g. Erik Diegmann">
      <button id="path-go" class="btn btn-primary">Find connection</button>
    </div>
    <label style="font-weight:normal;font-size:12px;margin-top:6px"><input type="checkbox" id="path-cross">&nbsp;Search across all scans (reaches entities found in other investigations)</label>
    <div id="path-result" style="margin-top:10px"></div>`;
  const out = $('#path-result');
  const run = async () => {
    const from = $('#path-from').value.trim(), to = $('#path-to').value.trim();
    if (!from || !to){ out.innerHTML = '<span class="text-muted">Enter two entity values to connect.</span>'; return; }
    const cross = $('#path-cross').checked;
    out.innerHTML = '<span class="text-muted">Searching the graph…</span>';
    let data;
    try { data = await API.path(id, from, to, null, cross); }
    catch(e){ out.innerHTML = `<div class="alert alert-danger" style="margin-bottom:0"><b>Error.</b> ${esc(e.message)}</div>`; return; }
    const paths = (data && data.paths) || [];
    const nodes = (data && data.nodes) || {};
    const label = uid => { const n = nodes[uid]; return n ? `${kindPill(n.kind)} <code>${esc(n.value)}</code>` : `<code class="text-muted" style="font-size:10px">${esc(String(uid).slice(0,12))}…</code>`; };
    if (!paths.length){
      out.innerHTML = `<div class="alert alert-warning" style="margin-bottom:0"><b>No connection found</b> between <code>${esc(from)}</code> and <code>${esc(to)}</code> in this scan's graph (within 6 hops). Run a deeper scan so the recursion draws in the linking entities.</div>`;
      return;
    }
    let html = `<p class="text-muted" style="font-size:12px;margin-bottom:8px"><b>${paths.length}</b> route${paths.length===1?'':'s'} found — shortest first.</p>`;
    paths.forEach((p, i) => {
      let chain = label(p.nodes[0]);
      for (let k=0; k<p.edges.length; k++){
        chain += ` <span class="text-muted">—<span class="tag" style="margin:0 3px">${esc(p.edges[k].kind)}</span>→</span> ${label(p.nodes[k+1])}`;
      }
      html += `<div style="margin-bottom:8px;padding:8px 10px;border-left:3px solid ${i===0?'#5cb85c':'#5bc0de'};background:rgba(127,127,127,0.06)">
        <div style="margin-bottom:4px"><span class="badge">${p.hops} hop${p.hops===1?'':'s'}</span> <span class="text-muted">· strength ${Number(p.strength).toFixed(2)}</span></div>
        <div style="line-height:2">${chain}</div>
      </div>`;
    });
    out.innerHTML = html;
  };
  $('#path-go').onclick = run;
  $('#path-from').onkeydown = e => { if (e.key === 'Enter') run(); };
  $('#path-to').onkeydown = e => { if (e.key === 'Enter') run(); };
}

