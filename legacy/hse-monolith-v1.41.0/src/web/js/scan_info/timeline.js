import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { renderTimelineHtml } from '/static/hse_wasm_ui.js';

/* ── Timeline section — the subject's footprint reconstructed as one chronology
   (when each breach/registration/account/expiry happened), oldest first. The
   server already parses every dated evidence attribute into typed events. The
   HTML templating lives in wasm-ui/src/scan_info/timeline.rs. ── */
export async function renderTimeline(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Reconstructing the timeline…</h3></div>';
  let data;
  try { data = await API.timeline(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  try { host.innerHTML = renderTimelineHtml(data); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; }
}
