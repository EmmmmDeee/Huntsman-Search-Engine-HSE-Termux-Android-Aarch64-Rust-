import { API } from '/static/js/api.js';
import { attr, esc, extLink, kindPill } from '/static/js/helpers.js';

/* ── Network section — the subject-centric relationship synthesis (the analyst's
   "so what": who/what the seed connects to, grouped + ranked server-side). ── */
export const NET_GROUP_ICON = {people:'glyphicon-user', identifiers:'glyphicon-envelope',
  aliases:'glyphicon-random', affiliations:'glyphicon-briefcase',
  locations:'glyphicon-map-marker', infrastructure:'glyphicon-cloud'};
export async function renderNetwork(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Building the subject network…</h3></div>';
  let net;
  try { net = await API.network(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  const browseLink = `#/scaninfo?id=${attr(id)}&tab=browse`;
  if (!net || !net.subject){
    host.innerHTML = `<div class="empty-state"><h3>No subject network yet</h3>
      <p>Connections appear once the scan derives relations — people, accounts, aliases,
      organisations and locations bound to the subject. Run a deeper scan (<code>--depth ≥ 1</code>) or open
      <a href="${browseLink}">Browse</a> for the raw entities.</p></div>`;
    return;
  }
  const s = net.subject;
  let html = `<div class="net-hero">
    <div class="net-hero-main">
      <div class="net-hero-name">${esc(s.value)}</div>
      <div class="net-hero-meta">${kindPill(s.kind)}
        <span class="cls c-${attr(s.classification)}">${esc(s.classification)}</span>
        <span class="text-muted" style="font-size:11px">C_eff ${(s.confidence||0).toFixed(2)}</span></div>
    </div>
    <div class="net-hero-stats">
      <div class="net-stat"><div class="v">${net.direct_count}</div><div class="l">direct</div></div>
      <div class="net-stat"><div class="v">${net.reachable_count}</div><div class="l">reachable</div></div>
      <div class="net-stat"><div class="v">${net.edge_count}</div><div class="l">edges</div></div>
    </div>
  </div>`;
  if (!net.groups || !net.groups.length){
    html += `<div class="empty-state"><p>The subject has no derived connections yet —
      <a href="${browseLink}">Browse</a> the raw entities, or run a deeper scan to map the network.</p></div>`;
  }
  for (const g of (net.groups||[])){
    const icon = NET_GROUP_ICON[g.key] || 'glyphicon-link';
    const more = g.total > g.items.length
      ? ` <span class="text-muted" style="font-weight:400;font-size:11px">top ${g.items.length} of ${g.total}</span>` : '';
    html += `<div class="net-group">
      <div class="net-group-head"><i class="glyphicon ${icon}"></i>&nbsp;${esc(g.label)}
        <span class="badge">${g.total}</span>${more}</div>`;
    for (const c of g.items){
      const conf = Math.max(0, Math.min(100, Math.round((c.edge_confidence||0)*100)));
      // The far-end node's TIER: the Connection struct separates edge_confidence
      // (how trusted the link is) from the node's own tier/entity_confidence
      // (how trusted the far entity is), but the row showed only the link bar —
      // so a CANDIDATE far-end read identically to a VERIFIED one. Surface the
      // tier pill (same styling as Browse) and carry the node confidence in its
      // tooltip, reconnecting both node-trust fields the synthesis computes.
      const tier = c.classification || '';
      const nodeConf = Math.round((Number(c.entity_confidence)||0)*100);
      const tierPill = tier
        ? `<span class="cls c-${attr(tier)}" title="far-end entity ${esc(tier)} · node confidence ${nodeConf}%">${esc(tier)}</span>`
        : '';
      html += `<div class="net-conn">
        <span class="net-rel">${esc(c.label)}</span>
        <span class="net-conn-val">${extLink(c.value, 72)}</span>
        ${kindPill(c.kind)}${tierPill}
        <span class="net-conf" title="link confidence ${conf}%"><span class="net-conf-bar" style="width:${conf}%"></span></span>
      </div>`;
    }
    html += `</div>`;
  }
  host.innerHTML = html;
}

