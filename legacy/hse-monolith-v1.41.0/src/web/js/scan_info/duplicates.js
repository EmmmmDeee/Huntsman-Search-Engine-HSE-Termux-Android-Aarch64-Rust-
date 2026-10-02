import { API } from '/static/js/api.js';
import { S } from '/static/js/state.js';
import { renderDuplicatesHtml } from '/static/hse_wasm_ui.js';

/* ── Likely-duplicates aid — near-duplicate entity-resolution suggestions
   (GET /scans/{id}/duplicates): probable same-identity groups the exact matcher
   missed (Gmail variants, phone formats, reordered names). Fails quietly.
   The HTML templating lives in wasm-ui/src/scan_info/duplicates.rs. ── */
export async function renderDuplicates(host, id){
  try { host.innerHTML = renderDuplicatesHtml(await API.duplicates(id), S.entities||[]); }
  catch(e){ host.innerHTML = ''; }
}

