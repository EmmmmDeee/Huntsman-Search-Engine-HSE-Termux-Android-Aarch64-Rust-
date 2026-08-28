import { attr, esc, kindPill } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';

// Card headers are cheap, but a cluster's member list can be hundreds of
// entities — one real scan had eleven 607-member clusters, ~52k member rows
// across all correlations. So: page the cards, and build each card's member
// rows LAZILY on first expand. Opening this tab is then O(cards shown), not
// O(total members), and never dumps tens of thousands of hidden DOM nodes.
const CORR_CARDS_PER_PAGE = 100;

/* ── Correlations tab ── */
export function renderCorrelations(host){
  if (!S.correlations.length){
    host.innerHTML = '<div class="empty-state"><h3>No correlations fired</h3><p>Correlation rules evaluate post-scan against the entities produced. They surface multi-source breach clusters, infrastructure consensus, and other high-signal aggregations.</p></div>';
    return;
  }
  // Server returns correlations pre-ranked by severity × max child C_eff
  // (highest-value first), so paging keeps the most important cards on top.
  const total = S.correlations.length;
  let shown = 0;
  const cardHtml = (c, idx)=>{
    const sev = (c.severity||'low').toLowerCase();
    const uids = c.entity_uids || [];
    const rank = (typeof c.rank === 'number' && c.rank > 0)
      ? `<span class="pull-right" title="rank = severity × max child C_eff">rank ${c.rank.toFixed(2)}</span>` : '';
    // Members are NOT built here — the .corr-members container is filled on first
    // expand by toggleCorrMembers(), keyed by data-corr-idx.
    return `<div class="corr-card cv-${attr(sev)}" data-corr-idx="${idx}" onclick="toggleCorrMembers(this)" style="cursor:pointer" title="Click to show the ${uids.length} linked entit${uids.length===1?'y':'ies'}">
      <div class="corr-h"><b>${esc(sev.toUpperCase())}</b> · ${esc(c.rule_id||'')} <span class="badge">${uids.length}</span>${rank}</div>
      <div class="corr-name">${esc(c.rule_name||c.rule_id||'—')}</div>
      <div class="corr-d">${esc(c.description||c.summary||'')}</div>
      <div class="corr-members" style="display:none;margin-top:8px;border-top:1px dashed #d8d8d8;padding-top:6px"></div>
    </div>`;
  };
  const nextPage = ()=>{
    const end = Math.min(shown + CORR_CARDS_PER_PAGE, total);
    const frag = S.correlations.slice(shown, end).map((c,i)=>cardHtml(c, shown+i)).join('');
    shown = end;
    return frag;
  };
  host.innerHTML = `<div id="corr-list">${nextPage()}</div><div id="corr-more" style="margin-top:12px"></div>`;
  const moreBox = host.querySelector('#corr-more');
  const paint = ()=>{
    moreBox.innerHTML = shown < total
      ? `<button type="button" class="btn btn-default btn-sm" id="corr-more-btn">Show ${Math.min(CORR_CARDS_PER_PAGE, total-shown)} more <span class="text-muted">(${total-shown} remaining)</span></button>`
      : `<div class="text-muted" style="font-size:12px">All ${total} correlations shown.</div>`;
    const b = moreBox.querySelector('#corr-more-btn');
    if (b) b.addEventListener('click', ()=>{ host.querySelector('#corr-list').insertAdjacentHTML('beforeend', nextPage()); paint(); });
  };
  paint();
}

export function toggleCorrMembers(card){
  const m = card.querySelector('.corr-members');
  if (!m) return;
  // Build the member rows the first time this card is opened, from S — so a
  // 607-member cluster costs its rows only when the operator asks to see them.
  if (!m.dataset.built){
    const c = S.correlations[Number(card.dataset.corrIdx)];
    const byUid = {};
    (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
    const uids = (c && c.entity_uids) || [];
    m.innerHTML = uids.map(u=>{
      const e = byUid[u];
      // A resolved member is clickable: pivot to it in the Browse tab (the
      // cross-reference becomes navigable). stopPropagation so it doesn't also
      // toggle the card.
      return e ? `<div class="corr-member" style="cursor:pointer" title="Show '${attr(e.value)}' in Browse"
                    data-pivot="${attr(e.value)}" onclick="event.stopPropagation();pivotToEntity(this.dataset.pivot)">${kindPill(e.kind)} <code>${esc(e.raw_value||e.value)}</code></div>`
                 : `<div class="corr-member"><code class="text-muted" style="font-size:10px">${esc(String(u).slice(0,16))}…</code></div>`;
    }).join('') || '<span class="text-muted">No member entities in this scan view</span>';
    m.dataset.built = '1';
  }
  m.style.display = (m.style.display==='none') ? '' : 'none';
}
/* Pivot from a correlation member (or anywhere) to that entity in the Browse
   tab, pre-filtered to its value — turns a "these are linked" insight into a
   one-click drill-in. */
export function pivotToEntity(value){
  const id = S.route.params.id;
  if (!id) return;
  nav(`#/scaninfo?id=${encodeURIComponent(id)}&tab=browse&q=${encodeURIComponent(value)}`);
}
