import { API } from '/static/js/api.js';
import { $, attr } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Graph tab (D3 v3 force layout — matches Spiderfoot's stack) ── */
export function renderGraph(host){
  if (!S.entities.length){
    host.innerHTML = '<div class="empty-state"><h3>No entities to graph</h3><p>The Graph view becomes available once the scan produces entities.</p></div>';
    return;
  }
  host.innerHTML = `
    <div style="position:relative">
      <svg id="graph-svg" preserveAspectRatio="xMidYMid meet"></svg>
      <div id="graph-cap" class="graph-cap text-muted" style="display:none"></div>
      <div class="graph-legend">
        <div class="lr"><span class="sw" style="background:#059CD7;border:2px solid #333"></span>seed target</div>
        <div class="lr"><span class="sw" style="background:#31708f"></span>email / ip</div>
        <div class="lr"><span class="sw" style="background:#3c763d"></span>domain</div>
        <div class="lr"><span class="sw" style="background:#2c7c40"></span>username</div>
        <div class="lr"><span class="sw" style="background:#8a6d3b"></span>phone</div>
        <div class="lr"><span class="sw" style="background:#9b1f9b"></span>credential</div>
        <div class="lr"><span class="sw" style="background:#d9822b"></span>relation edge (hover for kind)</div>
      </div>
      <div class="graph-ctl">
        <button class="btn btn-default btn-xs" id="g-relayout"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Re-layout</button>
        <button class="btn btn-default btn-xs" id="g-reset"><i class="glyphicon glyphicon-fullscreen"></i>&nbsp;Reset view</button>
        <a class="btn btn-default btn-xs" href="${API.gexfUrl(S.scan.id)}" data-download title="Export graph as GEXF (Gephi)"><i class="glyphicon glyphicon-export"></i>&nbsp;GEXF</a>
      </div>
      <div class="graph-hint text-muted">Drag nodes · pinch or scroll to zoom · drag canvas to pan</div>
    </div>
  `;
  buildD3Graph();
  $('#g-relayout').addEventListener('click', buildD3Graph);
  $('#g-reset').addEventListener('click', ()=>{ if (window.__graphResetZoom) window.__graphResetZoom(); });
}

export const NODE_COLOR = {
  email:'#31708f', domain:'#3c763d', username:'#2c7c40', phone:'#8a6d3b',
  ip_address:'#31708f', asn:'#5a4d8a', person:'#3c763d', credential:'#9b1f9b',
  password:'#9b1f9b', address:'#a94442', coordinates:'#8a4b1f', organisation:'#5a4d8a',
  abn_acn:'#8a6d3b', url:'#31708f', mac_address:'#666', device_id:'#666',
  // Kinds that previously fell back to the undifferentiated '#888' grey (matched
  // to their Browse pill colours so a kind reads the same in both surfaces).
  cidr:'#31708f', crypto_address:'#b8860b', api_key:'#c0392b', ssid:'#2c6e6a', tracking_id:'#5e4b8a',
  other:'#888'
};

// Graph rendering ceilings — keep the interactive SVG force graph legible and,
// above all, stop a large scan from locking up the browser tab. Correlation
// clusters routinely span hundreds of members (real scans produce several
// 600+-member clusters), so an unbounded render is not a corner case. See
// buildD3Graph() for how these are applied.
export const GRAPH_MAX_NODES = 240;  // entity nodes rendered (the seed is extra)
export const GRAPH_MAX_LINKS = 2000; // hard ceiling on edges handed to D3
export const CORR_MAX_SPOKES = 8;    // members linked per correlation (star, not clique)

export function buildD3Graph(){
  if (typeof d3==='undefined') return;
  // Theme-aware palette: the graph is drawn by D3 (inline styles), so the
  // CSS dark-theme rules can't reach the node labels / seed edges. Read the
  // active theme once per (re)layout and pick contrasting colours, so the
  // signature graph view stays legible in the default dark mode.
  const dark = document.body.classList.contains('dark-theme');
  const labelFill = dark ? '#cfcfcf' : '#444';
  const seedEdge  = dark ? '#4a4a4a' : '#bbb';
  const nodeHalo  = dark ? '#1a1a1a' : '#fff';
  const seedHalo  = dark ? '#fff'    : '#222';
  const svg = d3.select('#graph-svg');
  const rect = svg.node().getBoundingClientRect();
  const W = rect.width, H = rect.height || 560;
  svg.selectAll('*').remove();
  svg.attr('viewBox', `0 0 ${W} ${H}`);

  // Pan/zoom container — pinch-zoom + one-finger pan work natively on
  // Chrome-on-Android via d3 v3's touch-aware zoom behavior. Without this a
  // multi-node graph is unusable on a phone screen (SpiderFoot 4.0 parity).
  const container = svg.append('g').attr('class','zoom-container');
  const zoom = d3.behavior.zoom().scaleExtent([0.2, 5]).on('zoom', ()=>{
    container.attr('transform', `translate(${d3.event.translate})scale(${d3.event.scale})`);
  });
  svg.call(zoom).on('dblclick.zoom', null);
  // Expose a reset so the "Reset view" button can recentre/rescale.
  window.__graphResetZoom = ()=>{
    zoom.translate([0,0]).scale(1);
    container.transition().duration(250).attr('transform', 'translate(0,0)scale(1)');
  };

  // Build nodes/edges — bounded so the SVG force graph stays legible and, above
  // all, never locks up the tab. A large scan (1000+ entities, correlation
  // clusters spanning hundreds of members) is routine; drawing a *clique* per
  // correlation — the historical behaviour — is O(k²) and, for the 600+-member
  // clusters real scans produce, builds ~15M edges that hang or crash the
  // renderer and yield an unreadable hairball. We render the most-connected
  // slice of nodes and represent each correlation as a bounded *star*, not a
  // clique. Browse / Relations / GEXF remain the complete, unabridged views.
  const seedId = '__seed__';
  const nodes = [{id:seedId, kind:S.scan.target.kind, label:S.scan.target.value, isSeed:true, r:12}];

  // Rank entities by relation-degree (structural importance) then corroboration,
  // so that when we cap, the graph's connected core is what survives.
  const relList = S.relations || [];
  const relDegree = new Map();
  for (const r of relList){
    relDegree.set(r.from_uid, (relDegree.get(r.from_uid)||0)+1);
    relDegree.set(r.to_uid,   (relDegree.get(r.to_uid)||0)+1);
  }
  const ranked = S.entities.slice().sort((a,b)=>
    ((relDegree.get(b.uid)||0)-(relDegree.get(a.uid)||0)) ||
    ((b.corroboration??1)-(a.corroboration??1)));
  const shown = ranked.slice(0, GRAPH_MAX_NODES);
  const shownIds = new Set(shown.map(e=>e.uid));
  // Uid → entity, built once. The correlation-hub scan below needs an entity's
  // corroboration per member per correlation; doing that with
  // `S.entities.find(...)` is a linear scan inside two nested loops —
  // O(correlations × members × entities). A real 371-entity scan with 32
  // correlations is already millions of string comparisons on a phone CPU,
  // burned every re-layout, for a lookup a Map answers in O(1).
  const entityByUid = new Map(S.entities.map(e=>[e.uid, e]));
  for (const e of shown){
    nodes.push({id:e.uid, kind:e.kind, label:e.value, r: 5 + Math.min(8, Math.log(1+(e.corroboration??1))*3)});
  }

  // Links, in priority order so the global ceiling trims the least-important
  // first: typed relations → seed anchors → correlation stars. Only edges whose
  // endpoints are both rendered are built.
  const links = [];
  // Typed attribution edges (subdomain_of / belongs_to_domain / hosted_on /
  // derived_from / co_located_with) between entity nodes.
  for (const r of relList)
    if (shownIds.has(r.from_uid) && shownIds.has(r.to_uid))
      links.push({source:r.from_uid, target:r.to_uid, rel:true, kind:r.kind});
  for (const e of shown) links.push({source:seedId, target:e.uid, corr:false});
  for (const c of S.correlations){
    if (links.length >= GRAPH_MAX_LINKS) break;
    // Star instead of a k² clique — O(k), capped fan-out — keeping the "these
    // are one group" signal without the hairball or the millions of edges.
    // Anchor the star at the cluster's *most-connected* rendered member (by
    // relation degree, then corroboration), not an arbitrary storage-order
    // one, so the visual hub reflects real centrality rather than misleading.
    const members = (c.entity_uids || c.evidence_uids || c.entities || []).filter(u=>shownIds.has(u));
    if (members.length < 2) continue;
    // Pick hub by relation degree, then corroboration tie-break (per comment at line 131).
    let hub = members[0], hubScore = -1, hubCorr = -1;
    for (const u of members){
      const ent = entityByUid.get(u);
      const relScore = (relDegree.get(u)||0);
      const corrScore = ent?.corroboration ?? 1;
      if (relScore > hubScore || (relScore === hubScore && corrScore > hubCorr)){
        hub = u; hubScore = relScore; hubCorr = corrScore;
      }
    }
    let spokes = 0;
    for (const u of members){
      if (u === hub) continue;
      if (spokes >= CORR_MAX_SPOKES || links.length >= GRAPH_MAX_LINKS) break;
      links.push({source:hub, target:u, corr:true});
      spokes++;
    }
  }

  // Surface when the view is a summary, and point to the complete surfaces.
  const nodesCapped = shown.length < S.entities.length;
  const linksCapped = links.length >= GRAPH_MAX_LINKS;
  const capEl = $('#graph-cap');
  if (capEl){
    if (nodesCapped || linksCapped){
      capEl.style.display = '';
      capEl.textContent = `Showing the ${shown.length} most-connected of ${S.entities.length} entities`
        + (linksCapped ? ` · edges capped at ${GRAPH_MAX_LINKS}` : '')
        + ' — Browse, Relations, and the GEXF export carry the complete graph.';
    } else {
      capEl.style.display = 'none';
    }
  }

  // Drop links to unknown nodes, then resolve source/target to the actual
  // node object references. D3 v3's force layout only auto-resolves
  // *numeric* link.source/target (treating them as indices into .nodes());
  // our ids are entity UID strings, which it leaves untouched, so its
  // internal neighbor-seeding pass (`e[u.source.index].push(...)`) reads
  // `.index` off a bare string, gets undefined, and throws on the very
  // first `.start()` call for any scan with at least one entity. Handing
  // it real node references up front — same object identity the `tick`
  // handler below already expects via `d.source.x`/`d.target.x` — avoids
  // that path entirely.
  const ids = new Set(nodes.map(n=>n.id));
  const nodesById = new Map(nodes.map(n=>[n.id, n]));
  const validLinks = links
    .filter(l=>ids.has(l.source) && ids.has(l.target))
    .map(l=>({...l, source: nodesById.get(l.source), target: nodesById.get(l.target)}));

  const force = d3.layout.force()
    .nodes(nodes)
    .links(validLinks)
    .charge(-260)
    .linkDistance(90)
    .size([W, H])
    .start();
  // Pin seed at centre.
  const seedNode = nodes.find(n=>n.isSeed);
  if (seedNode){ seedNode.fixed = true; seedNode.x = W/2; seedNode.y = H/2; }

  const link = container.append('g').selectAll('line')
    .data(validLinks).enter().append('line')
    .style('stroke', d=>d.rel?'#d9822b':(d.corr?'#9b1f9b':seedEdge))
    .style('stroke-opacity', d=>d.rel?0.85:(d.corr?0.7:(dark?0.5:0.3)))
    .style('stroke-width', d=>d.rel?2:(d.corr?1.6:1))
    .style('stroke-dasharray', d=>d.rel?'5,3':'none');
  // Hover a typed edge to see its relation kind.
  link.append('title').text(d=>d.rel?('relation: '+d.kind):(d.corr?'correlation':'discovered from seed'));

  const drag = force.drag().on('dragstart', function(){ d3.select(this).style('cursor','grabbing'); });

  const nodeG = container.append('g').selectAll('g').data(nodes).enter().append('g').call(drag);
  // Stop a node-drag from also panning the canvas (d3 v3 zoom vs drag).
  nodeG.on('mousedown', ()=>{ if (d3.event) d3.event.stopPropagation(); });
  nodeG.append('circle')
    .attr('r', d=>d.r)
    .style('fill', d=>d.isSeed?'#059CD7':(NODE_COLOR[d.kind]||'#888'))
    .style('stroke', d=>d.isSeed?seedHalo:nodeHalo)
    .style('stroke-width', d=>d.isSeed?2:1.5)
    .style('cursor','grab');
  nodeG.append('title').text(d=>`${d.kind}: ${d.label}`);
  nodeG.append('text')
    .attr('dx', d=>d.r + 4)
    .attr('dy', 4)
    .style('font-size','11px')
    .style('fill',labelFill)
    .text(d=>{const l = d.label||''; return l.length>28?l.slice(0,26)+'…':l;});

  force.on('tick', ()=>{
    link.attr('x1', d=>d.source.x).attr('y1', d=>d.source.y)
        .attr('x2', d=>d.target.x).attr('y2', d=>d.target.y);
    nodeG.attr('transform', d=>`translate(${d.x},${d.y})`);
  });
  // Stop after a few seconds — saves CPU on Termux when the graph
  // is rendered but idle.
  setTimeout(()=>force.stop(), 6000);
}

