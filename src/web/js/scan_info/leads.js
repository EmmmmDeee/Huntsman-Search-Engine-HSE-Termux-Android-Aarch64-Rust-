import { API } from '/static/js/api.js';
import { $$, attr, esc, kindPill, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { NET_GROUP_ICON } from '/static/js/scan_info/network.js';

/* ── Leads tab — proactive next-best-actions: ranked untapped pivots the scan
   surfaced but didn't pursue (relatives/associates held below the auto-pivot
   floor most of all), each a one-click follow-up scan. ── */
export async function renderLeads(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Finding leads…</h3></div>';
  let data;
  try { data = await API.leads(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  const leads = (data && data.leads) || [];
  if (!leads.length){
    host.innerHTML = `<div class="empty-state"><h3>No open leads</h3>
      <p>Leads appear when a scan surfaces people, aliases or identifiers it didn't pursue —
      most often relatives and associates kept below the auto-pivot floor. Check the
      <a href="#/scaninfo?id=${attr(id)}&tab=network">Network</a>, or run a deeper scan.</p></div>`;
    return;
  }
  const confirmedN = leads.filter(l=>l.confirmed).length;
  let html = `<p class="text-muted" style="font-size:12px;margin-bottom:10px">
    <i class="glyphicon glyphicon-flag"></i>&nbsp;<b>${leads.length}</b> recommended next step${leads.length===1?'':'s'}
    — untapped pivots ranked by value, the${confirmedN?` <b>${confirmedN}</b> corroborated`:''} reliable ones first.
    Click <b>Scan</b> to launch a focused follow-up.</p>`;
  for (const l of leads){
    const icon = NET_GROUP_ICON[l.group] || 'glyphicon-flag';
    const badge = l.confirmed
      ? '<span class="lead-badge" title="An independent second signal corroborates this lead">✓ CONFIRMED</span>'
      : l.discordant
      ? '<span class="lead-badge namesake" title="Shares the surname but a whole region from the subject — likely a different person">⚠ NAMESAKE?</span>'
      : '';
    const cls = l.confirmed ? ' confirmed' : l.discordant ? ' discordant' : '';
    html += `<div class="lead-card${cls}">
      <div class="lead-main">
        <div class="lead-val"><i class="glyphicon ${icon}"></i>&nbsp;${esc(l.value)} ${kindPill(l.kind)}${badge}</div>
        <div class="lead-reason">${esc(l.reason)}</div>
      </div>
      <button class="btn btn-info btn-sm lead-scan" data-kind="${attr(l.target_kind)}" data-value="${attr(l.value)}"
        title="Launch a focused scan seeded on this lead">
        <i class="glyphicon glyphicon-search"></i>&nbsp;Scan</button>
    </div>`;
  }
  host.innerHTML = html;
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

