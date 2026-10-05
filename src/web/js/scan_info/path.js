import { API } from '/static/js/api.js';
import { $, esc } from '/static/js/helpers.js';
import { renderPathResultHtml } from '/static/hse_wasm_ui.js';

/* ── Connection-path tool — link analysis between two named entities. Enter two
   discovered values and find the shortest relationship chain linking them (plus
   alternative routes). GET /scans/{id}/path. The deeper the scan recursed, the more
   of the graph there is to connect across. The result templating lives in
   wasm-ui/src/scan_info/path.rs. ── */
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
    try { out.innerHTML = renderPathResultHtml(data, from, to); }
    catch(e){ out.innerHTML = `<div class="alert alert-danger" style="margin-bottom:0"><b>Error.</b> ${esc(e.message)}</div>`; }
  };
  $('#path-go').onclick = run;
  $('#path-from').onkeydown = e => { if (e.key === 'Enter') run(); };
  $('#path-to').onkeydown = e => { if (e.key === 'Enter') run(); };
}
