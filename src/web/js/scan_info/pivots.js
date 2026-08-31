import { API } from '/static/js/api.js';
import { S } from '/static/js/state.js';
import { renderPivotsHtml } from '/static/hse_wasm_ui.js';

/* ── Pivot nodes — the high-connectivity intermediaries most of the graph routes
   through (betweenness + degree centrality). GET /scans/{id}/pivots. The
   highest-leverage entities to pivot on next; read-only, structural. The HTML
   templating lives in wasm-ui/src/scan_info/pivots.rs. ── */
export async function renderPivots(host, id){
  try { host.innerHTML = renderPivotsHtml(await API.pivots(id), S.entities||[]); }
  catch(e){ host.innerHTML = ''; }
}

