import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Communities section — the relationship graph partitioned into sub-clusters by
   label propagation (the family cluster vs the infrastructure estate, …), each
   with its members and a derived label. GET /scans/{id}/communities. ── */
export async function renderCommunities(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Detecting communities…</h3></div>';
  let data;
  try { data = await API.communities(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  const comms = (data && data.communities) || [];
  if (!comms.length){
    host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-th-large"></i>&nbsp;Communities</h4>
      <div class="empty-state"><h3>No communities yet</h3>
      <p>Sub-clusters appear once the scan derives a connected relationship graph —
      run a deeper scan (<code>--depth ≥ 1</code>) so people, accounts and infrastructure link up.</p></div>`;
    return;
  }
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  const val = uid => { const e = byUid[uid]; return e ? esc(e.raw_value||e.value) : esc(String(uid).slice(0,12))+'…'; };
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-th-large"></i>&nbsp;Communities</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:10px"><b>${comms.length}</b> sub-cluster${comms.length===1?'':'s'} in the relationship graph, largest first.</p>`;
  for (const c of comms){
    const n = c.size || (c.uids||[]).length;
    const members = (c.uids||[]).slice(0,8).map(u=>`<code>${val(u)}</code>`).join(' ');
    const more = n > 8 ? ` <span class="text-muted">+${n-8} more</span>` : '';
    html += `<div style="margin-bottom:8px;padding:8px 10px;border-left:3px solid #5bc0de;background:rgba(91,192,222,0.07)">
      <div><span class="tag">${esc(c.label||('community '+c.id))}</span> <span class="text-muted">· ${n} member${n===1?'':'s'}</span></div>
      <div style="margin-top:4px;line-height:1.9">${members}${more}</div>
    </div>`;
  }
  host.innerHTML = html;
}

