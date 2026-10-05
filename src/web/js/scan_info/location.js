import { API } from '/static/js/api.js';
import { renderLocationHtml } from '/static/hse_wasm_ui.js';

/* ── Residency fix — the "where is the subject" verdict (AU-059). Powered by
      /scans/{id}/location. The map LINK opens OpenStreetMap in a new tab; it is
      a navigational anchor, NOT an embedded resource, so it stays within the
      airtight no-external-resource CSP. The HTML templating lives in
      wasm-ui/src/scan_info/location.rs. ── */
export async function renderLocation(host, id){
  try { host.innerHTML = renderLocationHtml(await API.location(id)); }
  catch(e){ host.innerHTML = ''; }
}

