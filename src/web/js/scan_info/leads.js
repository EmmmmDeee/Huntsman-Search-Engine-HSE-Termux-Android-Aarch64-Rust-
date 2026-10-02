import { API } from '/static/js/api.js';
import { $$, esc, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { renderLeadsHtml } from '/static/hse_wasm_ui.js';

/* ── Leads tab — proactive next-best-actions: ranked untapped pivots the scan
   surfaced but didn't pursue (relatives/associates held below the auto-pivot
   floor most of all), each a one-click follow-up scan. The HTML templating
   lives in wasm-ui/src/scan_info/leads.rs. ── */
export async function renderLeads(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Finding leads…</h3></div>';
  let data;
  try { data = await API.leads(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  try { host.innerHTML = renderLeadsHtml(data, id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  $$('.lead-scan').forEach(b=>b.addEventListener('click', async ()=>{
    const kind = b.dataset.kind, value = b.dataset.value;
    b.disabled = true; b.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>';
    try {
      const r = await API.create({kind, value, options:{}});
      toast('Lead scan queued');
      nav(`#/scaninfo?id=${r.scan_id}&tab=log`);
    } catch(e){
      b.disabled = false; b.innerHTML = '<i class="glyphicon glyphicon-search"></i>&nbsp;Scan';
      if (typeof alertify !== 'undefined') alertify.error('Scan failed: '+e.message);
    }
  }));
}
