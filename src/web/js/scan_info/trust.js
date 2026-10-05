import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { renderTrustHtml } from '/static/hse_wasm_ui.js';

/* ── Trust section — entities ranked by how strongly the relationship graph
   corroborates them (damped trust propagation from high-confidence anchors,
   attenuating with distance). GET /scans/{id}/trust. Read-only; never alters
   stored confidence — it is the network's vote, not raw per-entity confidence.
   The HTML templating lives in wasm-ui/src/scan_info/trust.rs. ── */
export async function renderTrust(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Propagating network trust…</h3></div>';
  let data;
  try { data = await API.trust(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  host.innerHTML = renderTrustHtml(data, S.entities||[]);
}

