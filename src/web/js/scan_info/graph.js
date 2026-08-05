import { API } from '/static/js/api.js';
import { $, attr } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Graph tab — dependency-free SVG renderer ──────────────────────────────
   This view used to be drawn by a vendored D3 v3 (151 KB) force layout. On the
   platform this tool actually targets — Termux on Android aarch64, no root,
   RAM shared with the OS — that was the single most expensive thing the UI did:
   a continuous physics simulation ticking over hundreds of nodes, mutating
   every `<line>` and `<g>` transform on every frame, while the same device was
   running the scan that produces those nodes.

   It is now a deterministic concentric layout: the seed sits at the centre and
   entities are placed on rings in rank order. Positions are computed once, in
   O(nodes), and nothing animates afterwards — there is no simulation to settle,
   so the graph appears instantly and then costs nothing until the operator
   touches it.

   Nothing was dropped to get there. Node colour by kind, radius by
   corroboration, truncated labels, hover tooltips, the legend, the capped-view
   notice, GEXF export, Re-layout, Reset view, node drag, and pinch/scroll zoom
   with canvas pan all still work — they are just implemented against the DOM
   directly (pointer events + a `transform` on one group) instead of through a
   rendering engine. The rendering ceilings below are unchanged. */
/* The operator's pan/zoom, kept OUTSIDE `buildGraph` so a rebuild does not
   throw it away.
 *
 * While a scan runs, scan-info re-renders every 8s and that re-runs
 * `renderGraph` → `buildGraph`. With the view state declared inside the build,
 * every one of those rebuilds snapped the canvas back to origin at scale 1 —
 * so for the whole duration of a scan the Graph tab could not usefully be
 * panned or zoomed at all: whatever the operator did was undone within eight
 * seconds. That is precisely when the graph is most worth exploring.
 *
 * Kept per-scan: `renderGraph` resets it when the mounted scan changes, so
 * opening a different scan starts centred rather than inheriting the previous
 * one's viewport. "Reset view" resets it on demand.
 *
 * Node positions are NOT preserved across a rebuild. `layoutConcentric` is
 * deterministic, so nodes that were already present land where they were as
 * long as the node set is unchanged; when the scan adds entities the layout
 * legitimately changes, and a dragged node returns to its computed place. */
const view = { x: 0, y: 0, k: 1 };
function resetView(){ view.x = 0; view.y = 0; view.k = 1; }
let viewScanId = null;

export function renderGraph(host){
  // A different scan gets a fresh viewport; the same scan re-rendering (the
  // 8s live refresh, or a tab switch back) keeps the operator's.
  const sid = S.scan && S.scan.id;
  if (viewScanId !== sid){ resetView(); viewScanId = sid; }
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
  buildGraph();
  $('#g-relayout').addEventListener('click', buildGraph);
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

// Graph rendering ceilings — keep the graph legible and, above all, stop a
// large scan from locking up the browser tab. Correlation clusters routinely
// span hundreds of members (real scans produce several 600+-member clusters),
// so an unbounded render is not a corner case. See buildGraph() for how these
// are applied.
export const GRAPH_MAX_NODES = 240;  // entity nodes rendered (the seed is extra)
export const GRAPH_MAX_LINKS = 2000; // hard ceiling on edges drawn
export const CORR_MAX_SPOKES = 8;    // members linked per correlation (star, not clique)

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(name, attrs){
  const e = document.createElementNS(SVG_NS, name);
  if (attrs) for (const k of Object.keys(attrs)) e.setAttribute(k, attrs[k]);
  return e;
}
const clamp = (v, lo, hi)=>v < lo ? lo : (v > hi ? hi : v);

/* Deterministic concentric placement. The seed is pinned at the centre and the
   remaining nodes — already sorted by structural importance — are laid onto
   rings outward, so the most-connected entities land nearest the seed. Ring
   capacity is derived from circumference so node spacing stays roughly constant
   as the graph grows. Pure arithmetic, O(nodes), no iteration to convergence. */
function layoutConcentric(nodes, W, H){
  const cx = W / 2, cy = H / 2;
  if (nodes.length) { nodes[0].x = cx; nodes[0].y = cy; }
  const rest = nodes.slice(1);
  if (!rest.length) return;
  // Ring spacing: fill the smaller viewport axis with however many rings the
  // node count needs, within sane bounds so small graphs are not sparse and
  // large ones stay on-canvas.
  const maxR = Math.max(120, Math.min(W, H) / 2 - 30);
  const rings = Math.max(1, Math.ceil(Math.sqrt(rest.length / 2.2)));
  const gap = maxR / rings;
  let i = 0, ring = 1;
  while (i < rest.length){
    const r = Math.min(maxR, ring * gap);
    // ~46px of arc per node keeps labels from colliding; always leave room for
    // at least 6 so the innermost ring is never degenerate.
    const capacity = Math.max(6, Math.floor((2 * Math.PI * r) / 46));
    const n = Math.min(capacity, rest.length - i);
    // Offset alternate rings by half a step so nodes do not line up radially.
    const off = (ring % 2 === 0) ? Math.PI / n : 0;
    for (let j = 0; j < n; j++){
      const a = (j / n) * 2 * Math.PI + off;
      rest[i + j].x = cx + r * Math.cos(a);
      rest[i + j].y = cy + r * Math.sin(a);
    }
    i += n;
    ring++;
  }
}

export function buildGraph(){
  const svg = $('#graph-svg');
  if (!svg) return;
  // Theme-aware palette: node labels and seed edges are set as presentation
  // attributes here, so the CSS dark-theme rules can't reach them. Read the
  // active theme once per (re)layout and pick contrasting colours.
  const dark = document.body.classList.contains('dark-theme');
  const labelFill = dark ? '#cfcfcf' : '#444';
  const seedEdge  = dark ? '#4a4a4a' : '#bbb';
  const nodeHalo  = dark ? '#1a1a1a' : '#fff';
  const seedHalo  = dark ? '#fff'    : '#222';

  const rect = svg.getBoundingClientRect();
  const W = rect.width || 800, H = rect.height || 560;
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // One group carries the pan/zoom transform; everything else is drawn inside.
  const container = svgEl('g', { class: 'zoom-container' });
  svg.appendChild(container);

  // Build nodes/edges — bounded so the graph stays legible and never locks up
  // the tab. A large scan (1000+ entities, correlation clusters spanning
  // hundreds of members) is routine; drawing a *clique* per correlation — the
  // historical behaviour — is O(k²) and, for the 600+-member clusters real
  // scans produce, builds ~15M edges that hang or crash the renderer and yield
  // an unreadable hairball. We render the most-connected slice of nodes and
  // represent each correlation as a bounded *star*, not a clique. Browse /
  // Relations / GEXF remain the complete, unabridged views.
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

  // Resolve endpoints to node objects and drop links to unknown nodes, so the
  // draw loop and the drag handler both read positions off one shared object
  // per node rather than re-looking-up ids.
  const nodesById = new Map(nodes.map(n=>[n.id, n]));
  const validLinks = links
    .filter(l=>nodesById.has(l.source) && nodesById.has(l.target))
    .map(l=>({...l, source: nodesById.get(l.source), target: nodesById.get(l.target)}));

  layoutConcentric(nodes, W, H);

  // ── Draw: edges first so nodes sit above them ──
  const linkG = svgEl('g');
  container.appendChild(linkG);
  const incident = new Map(); // node id → [{el, end}] for cheap drag updates
  for (const l of validLinks){
    const line = svgEl('line', {
      x1: l.source.x, y1: l.source.y, x2: l.target.x, y2: l.target.y,
      stroke: l.rel ? '#d9822b' : (l.corr ? '#9b1f9b' : seedEdge),
      'stroke-opacity': l.rel ? 0.85 : (l.corr ? 0.7 : (dark ? 0.5 : 0.3)),
      'stroke-width': l.rel ? 2 : (l.corr ? 1.6 : 1),
    });
    if (l.rel) line.setAttribute('stroke-dasharray', '5,3');
    const title = svgEl('title');
    title.textContent = l.rel ? ('relation: ' + l.kind) : (l.corr ? 'correlation' : 'discovered from seed');
    line.appendChild(title);
    linkG.appendChild(line);
    if (!incident.has(l.source.id)) incident.set(l.source.id, []);
    if (!incident.has(l.target.id)) incident.set(l.target.id, []);
    incident.get(l.source.id).push({el: line, end: 1});
    incident.get(l.target.id).push({el: line, end: 2});
  }

  const nodeLayer = svgEl('g');
  container.appendChild(nodeLayer);
  for (const n of nodes){
    const g = svgEl('g', { transform: `translate(${n.x},${n.y})`, cursor: 'grab' });
    g.appendChild(svgEl('circle', {
      r: n.r,
      fill: n.isSeed ? '#059CD7' : (NODE_COLOR[n.kind] || '#888'),
      stroke: n.isSeed ? seedHalo : nodeHalo,
      'stroke-width': n.isSeed ? 2 : 1.5,
    }));
    const t = svgEl('title');
    t.textContent = `${n.kind}: ${n.label}`;
    g.appendChild(t);
    const label = svgEl('text', {
      dx: n.r + 4, dy: 4, 'font-size': '11px', fill: labelFill,
    });
    const l = n.label || '';
    label.textContent = l.length > 28 ? l.slice(0, 26) + '…' : l;
    g.appendChild(label);
    n.el = g;
    nodeLayer.appendChild(g);
  }

  // ── Pan / zoom / drag, via pointer events (touch + mouse, no library) ──
  // `view` is module-scoped (see its declaration): the operator's pan and zoom
  // survive a rebuild, and are re-applied at the end of this function.
  const applyView = ()=>container.setAttribute('transform', `translate(${view.x},${view.y}) scale(${view.k})`);
  // Screen → viewBox units. The SVG is scaled to its box, so undo that first.
  const toViewBox = (clientX, clientY)=>{
    const b = svg.getBoundingClientRect();
    return {
      x: (clientX - b.left) * (W / (b.width || W)),
      y: (clientY - b.top) * (H / (b.height || H)),
    };
  };
  const toGraph = (clientX, clientY)=>{
    const p = toViewBox(clientX, clientY);
    return { x: (p.x - view.x) / view.k, y: (p.y - view.y) / view.k };
  };
  const zoomAt = (clientX, clientY, factor)=>{
    const p = toViewBox(clientX, clientY);
    const g = { x: (p.x - view.x) / view.k, y: (p.y - view.y) / view.k };
    view.k = clamp(view.k * factor, 0.2, 5);
    view.x = p.x - g.x * view.k;
    view.y = p.y - g.y * view.k;
    applyView();
  };

  window.__graphResetZoom = ()=>{ resetView(); applyView(); };

  svg.addEventListener('wheel', (ev)=>{
    ev.preventDefault();
    zoomAt(ev.clientX, ev.clientY, ev.deltaY < 0 ? 1.15 : 1 / 1.15);
  }, { passive: false });

  const pointers = new Map();      // pointerId → {clientX, clientY}
  let dragNode = null;             // node being dragged, if any
  let panFrom = null;              // {x, y} viewBox coords at pan start
  let pinchDist = 0;

  const moveNode = (n, gx, gy)=>{
    n.x = gx; n.y = gy;
    n.el.setAttribute('transform', `translate(${n.x},${n.y})`);
    for (const inc of (incident.get(n.id) || [])){
      inc.el.setAttribute(inc.end === 1 ? 'x1' : 'x2', n.x);
      inc.el.setAttribute(inc.end === 1 ? 'y1' : 'y2', n.y);
    }
  };

  for (const n of nodes){
    n.el.addEventListener('pointerdown', (ev)=>{
      ev.stopPropagation();          // a node drag must not also pan the canvas
      dragNode = n;
      n.el.setAttribute('cursor', 'grabbing');
      svg.setPointerCapture(ev.pointerId);
      pointers.set(ev.pointerId, { clientX: ev.clientX, clientY: ev.clientY });
    });
  }

  svg.addEventListener('pointerdown', (ev)=>{
    pointers.set(ev.pointerId, { clientX: ev.clientX, clientY: ev.clientY });
    if (pointers.size === 2){
      const [a, b] = Array.from(pointers.values());
      pinchDist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      panFrom = null;
      dragNode = null;
    } else if (!dragNode){
      const p = toViewBox(ev.clientX, ev.clientY);
      panFrom = { x: p.x - view.x, y: p.y - view.y };
      svg.setPointerCapture(ev.pointerId);
    }
  });

  svg.addEventListener('pointermove', (ev)=>{
    if (!pointers.has(ev.pointerId)) return;
    pointers.set(ev.pointerId, { clientX: ev.clientX, clientY: ev.clientY });
    if (pointers.size === 2 && pinchDist > 0){
      const [a, b] = Array.from(pointers.values());
      const d = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      if (d > 0){
        zoomAt((a.clientX + b.clientX) / 2, (a.clientY + b.clientY) / 2, d / pinchDist);
        pinchDist = d;
      }
      return;
    }
    if (dragNode){
      const g = toGraph(ev.clientX, ev.clientY);
      moveNode(dragNode, g.x, g.y);
    } else if (panFrom){
      const p = toViewBox(ev.clientX, ev.clientY);
      view.x = p.x - panFrom.x;
      view.y = p.y - panFrom.y;
      applyView();
    }
  });

  const endPointer = (ev)=>{
    pointers.delete(ev.pointerId);
    if (dragNode){ dragNode.el.setAttribute('cursor', 'grab'); dragNode = null; }
    if (pointers.size < 2) pinchDist = 0;
    if (pointers.size === 0) panFrom = null;
  };
  svg.addEventListener('pointerup', endPointer);
  svg.addEventListener('pointercancel', endPointer);

  applyView();
}
