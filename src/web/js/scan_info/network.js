import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { renderNetworkHtml } from '/static/hse_wasm_ui.js';

/* ── Network section — the subject-centric relationship synthesis (the analyst's
   "so what": who/what the seed connects to, grouped + ranked server-side). The
   HTML templating lives in wasm-ui/src/scan_info/network.rs. ── */
export const NET_GROUP_ICON = {people:'glyphicon-user', identifiers:'glyphicon-envelope',
  aliases:'glyphicon-random', affiliations:'glyphicon-briefcase',
  locations:'glyphicon-map-marker', infrastructure:'glyphicon-cloud'};
export async function renderNetwork(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Building the subject network…</h3></div>';
  let net;
  try { net = await API.network(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  try { host.innerHTML = renderNetworkHtml(net, id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; }
}
