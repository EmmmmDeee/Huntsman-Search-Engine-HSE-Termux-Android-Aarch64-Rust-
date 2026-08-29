import { API } from '/static/js/api.js';
import { renderGapsHtml } from '/static/hse_wasm_ui.js';

/* ── Discovery gaps — validated seeds with no evidence-backed link, why they're
   isolated, and the corrective scans that would connect them. GET /scans/{id}/gaps.
   The gap-resolution loop made legible: turns "no links" into "run these next".
   The HTML templating lives in wasm-ui/src/scan_info/gaps.rs. ── */
export async function renderGaps(host, id){
  try { host.innerHTML = renderGapsHtml(await API.gaps(id)); }
  catch(e){ host.innerHTML = ''; }
}

