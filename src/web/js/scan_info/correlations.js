import { attr, esc, kindPill } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';

/* ── Correlations tab ── */
export function renderCorrelations(host){
  if (!S.correlations.length){
    host.innerHTML = '<div class="empty-state"><h3>No correlations fired</h3><p>Correlation rules evaluate post-scan against the entities produced. They surface multi-source breach clusters, infrastructure consensus, and other high-signal aggregations.</p></div>';
    return;
  }
  // Server returns correlations pre-ranked by severity × max child C_eff
  // (highest-value first). Surface the rank score so the ordering is legible.
  // Each card expands to the entities it links (resolved against this scan),
  // so the cross-correlation is inspectable — SpiderFoot's correlation drill-in.
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  host.innerHTML = S.correlations.map(c=>{
    const sev = (c.severity||'low').toLowerCase();
    const rank = (typeof c.rank === 'number' && c.rank > 0)
      ? `<span class="pull-right" title="rank = severity × max child C_eff">rank ${c.rank.toFixed(2)}</span>` : '';
    const uids = c.entity_uids || [];
    const members = uids.map(u=>{
      const e = byUid[u];
      // A resolved member is clickable: pivot to it in the Browse tab (the
      // cross-reference becomes navigable). stopPropagation so it doesn't also
      // toggle the card.
      return e ? `<div class="corr-member" style="cursor:pointer" title="Show '${attr(e.value)}' in Browse"
                    data-pivot="${attr(e.value)}" onclick="event.stopPropagation();pivotToEntity(this.dataset.pivot)">${kindPill(e.kind)} <code>${esc(e.raw_value||e.value)}</code></div>`
               : `<div class="corr-member"><code class="text-muted" style="font-size:10px">${esc(String(u).slice(0,16))}…</code></div>`;
    }).join('');
    return `<div class="corr-card cv-${attr(sev)}" onclick="toggleCorrMembers(this)" style="cursor:pointer" title="Click to show the ${uids.length} linked entit${uids.length===1?'y':'ies'}">
      <div class="corr-h"><b>${esc(sev.toUpperCase())}</b> · ${esc(c.rule_id||'')} <span class="badge">${uids.length}</span>${rank}</div>
      <div class="corr-name">${esc(c.rule_name||c.rule_id||'—')}</div>
      <div class="corr-d">${esc(c.description||c.summary||'')}</div>
      <div class="corr-members" style="display:none;margin-top:8px;border-top:1px dashed #d8d8d8;padding-top:6px">${members||'<span class="text-muted">No member entities in this scan view</span>'}</div>
    </div>`;
  }).join('');
}
export function toggleCorrMembers(card){
  const m = card.querySelector('.corr-members');
  if (m) m.style.display = (m.style.display==='none') ? '' : 'none';
}
/* Pivot from a correlation member (or anywhere) to that entity in the Browse
   tab, pre-filtered to its value — turns a "these are linked" insight into a
   one-click drill-in. */
export function pivotToEntity(value){
  const id = S.route.params.id;
  if (!id) return;
  nav(`#/scaninfo?id=${encodeURIComponent(id)}&tab=browse&q=${encodeURIComponent(value)}`);
}

