import { API } from '/static/js/api.js';
import { esc, kindPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Trust section — entities ranked by how strongly the relationship graph
   corroborates them (damped trust propagation from high-confidence anchors,
   attenuating with distance). GET /scans/{id}/trust. Read-only; never alters
   stored confidence — it is the network's vote, not raw per-entity confidence. ── */
export async function renderTrust(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Propagating network trust…</h3></div>';
  let data;
  try { data = await API.trust(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  const scores = (data && data.trust) || [];
  if (!scores.length){
    host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-stats"></i>&nbsp;Network trust</h4>
      <div class="empty-state"><h3>No trust ranking yet</h3>
      <p>Trust radiates across the relationship graph from high-confidence anchors.
      It appears once the scan derives relations — run a deeper scan to populate it.</p></div>`;
    return;
  }
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  const top = scores.slice(0,12);
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-stats"></i>&nbsp;Network trust</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:10px">Top ${top.length} entit${top.length===1?'y':'ies'} by graph-corroborated trust — how strongly the network supports each, not raw confidence.</p>`;
  for (const t of top){
    const e = byUid[t.uid];
    const label = e ? `${kindPill(e.kind)} <code>${esc(e.raw_value||e.value)}</code>`
                    : `<code class="text-muted" style="font-size:10px">${esc(String(t.uid).slice(0,16))}…</code>`;
    const score = Number(t.score) || 0;
    const pct = Math.max(0, Math.min(100, Math.round(score*100)));
    html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
      <div style="flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${label}</div>
      <div style="flex:0 0 120px;background:rgba(127,127,127,0.2);border-radius:3px;height:10px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:#5cb85c"></div></div>
      <div style="flex:0 0 38px;text-align:right"><code>${score.toFixed(2)}</code></div>
    </div>`;
  }
  host.innerHTML = html;
}

