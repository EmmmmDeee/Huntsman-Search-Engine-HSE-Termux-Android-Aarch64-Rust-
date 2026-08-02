import { API } from '/static/js/api.js';
import { esc, kindPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Pivot nodes — the high-connectivity intermediaries most of the graph routes
   through (betweenness + degree centrality). GET /scans/{id}/pivots. The
   highest-leverage entities to pivot on next; read-only, structural. ── */
export async function renderPivots(host, id){
  let data;
  try { data = await API.pivots(id); }
  catch(e){ host.innerHTML = ''; return; }
  const pivots = (data && data.pivots) || [];
  const bridges = (data && data.bridges) || [];
  if (!pivots.length && !bridges.length){ host.innerHTML = ''; return; }
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  const labelFor = (uid) => {
    const e = byUid[uid];
    return e ? `${kindPill(e.kind)} <code>${esc(e.raw_value||e.value)}</code>`
             : `<code class="text-muted" style="font-size:10px">${esc(String(uid).slice(0,16))}…</code>`;
  };
  const top = pivots.slice(0, 12);
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-screenshot"></i>&nbsp;Pivot nodes</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:10px">The high-connectivity intermediaries most of the graph routes through — the highest-leverage entities to pivot on next. A <span class="label label-warning">critical</span> node is a single point of failure: remove it and the network fragments.</p>`;
  for (const p of top){
    const pctw = Math.max(0, Math.min(100, Math.round((Number(p.score)||0)*100)));
    const cut = p.is_cut_vertex ? ` <span class="label label-warning" title="Cut vertex — removing this entity fragments the network into disconnected pieces">critical</span>` : '';
    // coreness: k-core index. 0 = isolated periphery; higher = more deeply embedded.
    // ≥2 renders as a coloured badge (robust core member); 1 and 0 are muted.
    const cn = Number(p.coreness)||0;
    const cnBadge = cn >= 2
      ? ` <span class="label label-info" title="Coreness ${cn} — member of the ${cn}-core (redundantly corroborated; robust against single-entity removal)">⬡${cn}</span>`
      : cn === 1
        ? ` <span class="text-muted" style="font-size:10px" title="Coreness 1 — connected but not in a dense cluster">⬡1</span>`
        : '';
    html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
      <div style="flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${labelFor(p.uid)}${cut}${cnBadge}</div>
      <div class="text-muted" style="flex:0 0 auto;font-size:11px">${p.degree} link${p.degree===1?'':'s'}</div>
      <div style="flex:0 0 110px;background:rgba(127,127,127,0.2);border-radius:3px;height:10px;overflow:hidden">
        <div style="width:${pctw}%;height:100%;background:#9b59b6"></div></div>
    </div>`;
  }
  if (bridges.length){
    html += `<h5 style="margin:14px 0 4px"><i class="glyphicon glyphicon-resize-horizontal"></i>&nbsp;Critical links <span class="text-muted" style="font-weight:normal;font-size:11px">(${bridges.length} bridge${bridges.length===1?'':'s'})</span></h5>
      <p class="text-muted" style="font-size:12px;margin-bottom:6px">Single relationships whose removal would split the graph in two — irreplaceable connections to corroborate first.</p>`;
    for (const br of bridges.slice(0, 12)){
      html += `<div style="font-size:12px;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${labelFor(br.from_uid)} <span class="text-muted">—</span> ${labelFor(br.to_uid)}</div>`;
    }
    if (bridges.length > 12){ html += `<div class="text-muted" style="font-size:11px">…and ${bridges.length-12} more.</div>`; }
  }
  host.innerHTML = html;
}

