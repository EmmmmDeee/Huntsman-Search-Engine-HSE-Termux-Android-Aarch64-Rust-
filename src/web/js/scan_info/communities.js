import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { renderCommunitiesHtml } from '/static/hse_wasm_ui.js';

/* ── Communities section — the relationship graph partitioned into sub-clusters by
   label propagation (the family cluster vs the infrastructure estate, …), each
   with its members and a derived label. GET /scans/{id}/communities. The HTML
   templating lives in wasm-ui/src/scan_info/communities.rs; the loading
   placeholder and error message stay here since they wrap the async fetch. ── */
export async function renderCommunities(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Detecting communities…</h3></div>';
  let data;
  try { data = await API.communities(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  host.innerHTML = renderCommunitiesHtml(data, S.entities||[]);
}

