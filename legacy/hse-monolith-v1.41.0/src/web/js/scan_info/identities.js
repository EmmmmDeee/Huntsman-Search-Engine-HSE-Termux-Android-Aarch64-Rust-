import { API } from '/static/js/api.js';
import { renderIdentitiesHtml } from '/static/hse_wasm_ui.js';

/* ── Identities — people-centric co-reference resolution (which selectors name
      the same individual). Powered by /scans/{id}/identities. The HTML
      templating (incl. escaping) lives in wasm-ui/src/scan_info/identities.rs;
      fetching stays here since that's JS's job, not WASM's. ── */
export async function renderIdentities(host, id){
  try { host.innerHTML = renderIdentitiesHtml(await API.identities(id)); }
  catch(e){ host.innerHTML = ''; }
}

