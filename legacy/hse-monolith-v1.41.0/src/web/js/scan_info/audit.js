import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { renderAuditHtml } from '/static/hse_wasm_ui.js';

/* ── Audit tab — scored self-audit (GET /scans/{id}/audit). The HTML
   templating lives in wasm-ui/src/scan_info/audit.rs. ── */
export async function renderAudit(host, id){
  host.innerHTML = '<p class="text-muted">Auditing scan…</p>';
  let r;
  try { r = await API.auditScan(id); }
  catch(e){ host.innerHTML = `<div class="empty-state"><h3>Audit unavailable</h3><p>${esc(e.message)}</p></div>`; return; }
  try { host.innerHTML = renderAuditHtml(r, id); }
  catch(e){ host.innerHTML = `<div class="empty-state"><h3>Audit unavailable</h3><p>${esc(e.message)}</p></div>`; }
}
