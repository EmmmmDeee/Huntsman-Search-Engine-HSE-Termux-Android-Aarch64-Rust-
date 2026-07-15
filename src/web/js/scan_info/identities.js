import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';

/* ── Identities — people-centric co-reference resolution (which selectors name
      the same individual). Powered by /scans/{id}/identities. ── */
export async function renderIdentities(host, id){
  let data;
  try { data = await API.identities(id); }
  catch(e){ host.innerHTML = ''; return; }
  const refs = (data && data.coreferences) || [];
  if (!refs.length){ host.innerHTML = ''; return; }
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-user"></i>&nbsp;Resolved identities</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:8px">${refs.length} selector pair${refs.length===1?'':'s'} that score as the same individual (≥ ${esc(data.min_score)}).</p>`;
  for (const r of refs){
    const sig = (r.signals||[]).map(s=>`<span class="label label-default">${esc(s)}</span>`).join(' ');
    html += `<div style="margin-bottom:6px;padding:6px 10px;border-left:3px solid #5bc0de;background:rgba(91,192,222,0.07)">
      <div><code>${esc(r.value_a)}</code> <span class="text-muted">≈</span> <code>${esc(r.value_b)}</code>
        <span class="pull-right text-muted" style="font-size:11px">score ${(Number(r.score)||0).toFixed(2)}</span></div>
      <div style="margin-top:2px">${sig}</div>
    </div>`;
  }
  host.innerHTML = html;
}

