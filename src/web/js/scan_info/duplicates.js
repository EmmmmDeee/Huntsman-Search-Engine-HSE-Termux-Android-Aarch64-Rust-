import { API } from '/static/js/api.js';
import { esc, kindPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Likely-duplicates aid — near-duplicate entity-resolution suggestions
   (GET /scans/{id}/duplicates): probable same-identity groups the exact matcher
   missed (Gmail variants, phone formats, reordered names). Fails quietly. ── */
export async function renderDuplicates(host, id){
  let data;
  try { data = await API.duplicates(id); }
  catch(e){ host.innerHTML = ''; return; }
  const groups = (data && data.duplicates) || [];
  if (!groups.length){ host.innerHTML = ''; return; }
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  const val = uid => { const e = byUid[uid]; return e ? esc(e.raw_value||e.value) : esc(String(uid).slice(0,12))+'…'; };
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-duplicate"></i>&nbsp;Likely duplicates</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:8px">${groups.length} group${groups.length===1?'':'s'} that are probably one identity in different contexts — confirm before treating as the same.</p>`;
  for (const g of groups){
    const members = (g.members||[]).map(u=>`<code>${val(u)}</code>`).join(' ');
    html += `<div style="margin-bottom:6px;padding:6px 10px;border-left:3px solid #f0ad4e;background:rgba(240,173,78,0.07)">
      <div>${kindPill(g.kind)} ${members}</div>
      <div class="text-muted" style="font-size:11px;margin-top:2px">${esc(g.reason||'')}</div>
    </div>`;
  }
  host.innerHTML = html;
}

