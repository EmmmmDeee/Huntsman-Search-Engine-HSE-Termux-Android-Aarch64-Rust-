import { API } from '/static/js/api.js';

/* ── Scan-quality dashboard — objective per-scan telemetry (GET /scans/{id}/metrics):
   how much corroborated intelligence the scan formed. A nicety, so it fails quietly. ── */
export async function renderMetrics(host, id){
  let m;
  try { m = await API.metrics(id); }
  catch(e){ host.innerHTML = ''; return; }
  if (!m || !m.total_entities){ host.innerHTML = ''; return; }
  const pct = x => Math.round((Number(x)||0)*100);
  const t = m.tier_counts || {verified:0, probable:0, candidate:0};
  const stat = (lab, val) => `<div style="flex:0 0 auto;min-width:80px;padding:6px 10px;background:rgba(127,127,127,0.07);border-radius:4px;text-align:center">`
    + `<div style="font-size:18px;font-weight:600;line-height:1.1">${val}</div>`
    + `<div class="text-muted" style="font-size:11px">${lab}</div></div>`;
  host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-dashboard"></i>&nbsp;Scan quality</h4>
    <div style="display:flex;gap:6px;flex-wrap:wrap">`
    + stat('Entities', m.total_entities)
    + stat('Verified', t.verified)
    + stat('Relations', m.total_relations)
    + stat('Corroborated', pct(m.corroborated_fraction)+'%')
    + stat('Linked', pct(m.linked_entity_fraction)+'%')
    + ((m.seed_reach && m.seed_reach.anchored) ? stat('Reach', m.seed_reach.reachable_total) + stat('Max depth', m.seed_reach.max_depth+' hop'+(m.seed_reach.max_depth===1?'':'s')) : '')
    + stat('Graph density', pct(m.graph_density)+'%')
    + stat('Cross-scan', m.cross_scan_bridges)
    + stat('Mean conf', (Number(m.mean_confidence)||0).toFixed(2))
    + stat('Sources', m.distinct_evidence_sources)
    + `</div>`;
}

