import { API } from '/static/js/api.js';
import { $, attr } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Graph tab — a basic 2D flow chart, dependency-free ────────────────────
   This view first replaced a vendored D3 v3 force layout with a deterministic
   concentric (ring) node-link graph. That was still a GRAPH-VISUALISATION
   idiom — free-floating circles at computed radii, connected by lines with no
   inherent direction or reading order. Per the maintainer's direction it is
   now a FLOW CHART instead: rectangular boxes in rows, one row per expansion
   generation (row 0 = the seed; row N = entities first found N generations of
   pivoting later), with arrows showing which entity led to which. That is a
   more literal, more readable rendering of what a scan actually IS — a
   directed process of discovery — than a bag of circles ever was.

   Still deterministic, still O(nodes), still nothing animates after the
   initial draw — it costs nothing until the operator touches it, same as
   before. Node dragging is gone: a flow chart's positions are the STRUCTURE
   (which row, which rank within the row), not something to rearrange, so
   letting an operator drag a box out of its row would misrepresent the very
   thing the chart exists to show. That also deletes a real chunk of pointer-
   tracking code that existed only to keep a dragged node's edges attached to
   it — with nothing left to drag, there is nothing left to keep attached.

   Kept: node colour by kind, truncated labels, hover tooltips, the legend,
   the capped-view notice, GEXF export, Reset view, and pinch/scroll zoom with
   canvas pan. Also kept, but now genuinely meaningful rather than cosmetic:
   `derived_from` relations (which entity's discovery led to which) become the
   primary flow-chart arrows, and a plain "found via the seed" line is drawn
   ONLY for entities with no more specific lineage or relation edge — the prior
   graph anchored EVERY entity to the seed unconditionally, on top of its
   relation/correlation edges, which was redundant clutter a flow chart
   shouldn't repeat.

   Dropped, and not replaced: "Re-layout". It re-ran the SAME deterministic
   layout function on unchanged input — already a no-op click even before this
   rewrite, since the prior ring layout was pure arithmetic over an
   already-sorted node list with no randomness to reshuffle. A control with no
   observable effect is dead weight, not a feature to preserve. */
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
 * one's viewport. "Reset view" resets it on demand. */
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
        <div class="lr"><span class="sw" style="background:#d9822b"></span>lineage arrow (hover for kind)</div>
      </div>
      <div class="graph-ctl">
        <button class="btn btn-default btn-xs" id="g-reset"><i class="glyphicon glyphicon-fullscreen"></i>&nbsp;Reset view</button>
        <a class="btn btn-default btn-xs" href="${API.gexfUrl(S.scan.id)}" data-download title="Export graph as GEXF (Gephi)"><i class="glyphicon glyphicon-export"></i>&nbsp;GEXF</a>
      </div>
      <div class="graph-hint text-muted">Pinch or scroll to zoom · drag canvas to pan</div>
    </div>
  `;
  buildGraph();
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

// Graph rendering ceilings — keep the chart legible and, above all, stop a
// large scan from locking up the browser tab. Correlation clusters routinely
// span hundreds of members (real scans produce several 600+-member clusters),
// so an unbounded render is not a corner case. See buildGraph() for how these
// are applied.
export const GRAPH_MAX_NODES = 240;  // entity nodes rendered (the seed is extra)
export const GRAPH_MAX_LINKS = 2000; // hard ceiling on edges drawn
export const CORR_MAX_SPOKES = 8;    // members linked per correlation (star, not clique)

// Flow-chart box geometry — fixed size for every non-seed node, deliberately:
// a flow chart's boxes are uniform by convention, and a fixed size keeps the
// row/column layout arithmetic trivial (no per-node measurement pass).
const BOX_W = 132, BOX_H = 34, SEED_W = 150, SEED_H = 40;
const ROW_GAP = 78;     // vertical distance between generation rows
const COL_GAP = 18;     // horizontal gap between boxes in the same row
const ROW_TOP = 50;     // top margin before row 0 (the seed)

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(name, attrs){
  const e = document.createElementNS(SVG_NS, name);
  if (attrs) for (const k of Object.keys(attrs)) e.setAttribute(k, attrs[k]);
  return e;
}
const clamp = (v, lo, hi)=>v < lo ? lo : (v > hi ? hi : v);

/* Deterministic flow-chart placement: one row per expansion generation.
   `nodes[0]` (the seed) occupies row 0 alone; every other node carries a
   `gen` (its entity's `generation`, defaulted to 0) and is placed in row
   `gen + 1`, left-to-right in the rank order the caller already sorted it
   into (most structurally significant first). Pure arithmetic, O(nodes), no
   iteration to convergence — same complexity budget as the layout this
   replaces, just organised by "how many pivots from the seed" instead of "how
   many rings from the centre", which is the literal structure of a scan. */
function layoutFlowchart(nodes, W){
  if (!nodes.length) return;
  const seed = nodes[0];
  seed.w = SEED_W; seed.h = SEED_H;
  seed.x = W / 2; seed.y = ROW_TOP;

  const rows = new Map(); // generation -> [nodes], in the order they arrive (already rank-sorted)
  for (const n of nodes.slice(1)){
    const g = Math.max(0, n.gen || 0);
    if (!rows.has(g)) rows.set(g, []);
    rows.get(g).push(n);
  }
  const gens = Array.from(rows.keys()).sort((a, b) => a - b);
  gens.forEach((g, i) => {
    const rowNodes = rows.get(g);
    const y = ROW_TOP + (i + 1) * ROW_GAP;
    const rowWidth = rowNodes.length * BOX_W + (rowNodes.length - 1) * COL_GAP;
    // Centre the row when it fits the viewport; otherwise start at a fixed
    // left margin and let pan/zoom (unchanged) reach the overflow — the same
    // trade-off the ring layout made for a ring wider than the viewport.
    const startX = rowWidth <= W ? (W - rowWidth) / 2 : COL_GAP;
    rowNodes.forEach((n, j) => {
      n.w = BOX_W; n.h = BOX_H;
      n.x = startX + j * (BOX_W + COL_GAP) + BOX_W / 2;
      n.y = y;
    });
  });
}

export function buildGraph(){
  const svg = $('#graph-svg');
  if (!svg) return;
  // Theme-aware palette: node labels and seed edges are set as presentation
  // attributes here, so the CSS dark-theme rules can't reach them. Read the
  // active theme once per (re)layout and pick contrasting colours.
  const dark = document.body.classList.contains('dark-theme');
  const labelFill = dark ? '#e8e8e8' : '#222';
  const seedEdge  = dark ? '#4a4a4a' : '#bbb';
  const boxHalo   = dark ? '#1a1a1a' : '#fff';
  const seedHalo  = dark ? '#fff'    : '#222';

  const rect = svg.getBoundingClientRect();
  const W = rect.width || 800, H = rect.height || 560;
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // Arrowhead marker for lineage edges — drawn once, referenced by every
  // `derived_from` line via `marker-end`. Flow-chart arrows are directional
  // (parent -> child); the star/seed edges below stay plain lines, matching
  // their undirected "these are associated" semantic.
  const defs = svgEl('defs');
  const marker = svgEl('marker', {
    id: 'flow-arrow', viewBox: '0 0 10 10', refX: '9', refY: '5',
    markerWidth: '6', markerHeight: '6', orient: 'auto-start-reverse',
  });
  marker.appendChild(svgEl('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: '#d9822b' }));
  defs.appendChild(marker);
  svg.appendChild(defs);

  // One group carries the pan/zoom transform; everything else is drawn inside.
  const container = svgEl('g', { class: 'zoom-container' });
  svg.appendChild(container);

  // Build nodes/edges — bounded so the chart stays legible and never locks up
  // the tab. A large scan (1000+ entities, correlation clusters spanning
  // hundreds of members) is routine; drawing a *clique* per correlation — the
  // historical behaviour — is O(k²) and, for the 600+-member clusters real
  // scans produce, builds ~15M edges that hang or crash the renderer and yield
  // an unreadable hairball. We render the most-connected slice of nodes and
  // represent each correlation as a bounded *star*, not a clique. Browse /
  // Relations / GEXF remain the complete, unabridged views.
  const seedId = '__seed__';
  const nodes = [{id:seedId, kind:S.scan.target.kind, label:S.scan.target.value, isSeed:true}];

  // Rank entities by relation-degree (structural importance) then corroboration,
  // so that when we cap, the chart's connected core is what survives — and,
  // new here, so each row lists its most significant entities first (left).
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
  for (const e of shown){
    // `generation` is how many pivots from the seed this entity was first
    // found at (0 = seed round) — see Entity's doc comment. Row = gen + 1,
    // since row 0 is reserved for the seed itself.
    nodes.push({id:e.uid, kind:e.kind, label:e.value, gen: e.generation ?? 0});
  }

  // Links, in priority order so the global ceiling trims the least-important
  // first: typed relations (lineage first) → correlation stars → a "found via
  // the seed" fallback for whatever is still unconnected. Only edges whose
  // endpoints are both rendered are built.
  const links = [];
  const touched = new Set(); // node ids with at least one edge already
  // Typed attribution edges. `derived_from` is the literal expansion-lineage
  // arrow (child -> the entity that led to it) and is the chart's primary
  // "flow"; every other kind (subdomain_of / belongs_to_domain / hosted_on /
  // identified_by / alias_of / located_at / associated_with / same_as / …)
  // is drawn too, distinguished only by omitting the arrowhead, since those
  // assert an association rather than a discovery order.
  for (const r of relList){
    if (!(shownIds.has(r.from_uid) && shownIds.has(r.to_uid))) continue;
    links.push({source:r.from_uid, target:r.to_uid, rel:true, kind:r.kind, lineage: r.kind === 'derived_from'});
    touched.add(r.from_uid); touched.add(r.to_uid);
  }
  for (const c of S.correlations){
    if (links.length >= GRAPH_MAX_LINKS) break;
    // Star instead of a k² clique — O(k), capped fan-out — keeping the "these
    // are one group" signal without the hairball or the millions of edges.
    // Anchor the star at the cluster's *most-connected* rendered member (by
    // relation degree, then corroboration), not an arbitrary storage-order
    // one, so the visual hub reflects real centrality rather than misleading.
    const members = (c.entity_uids || c.evidence_uids || c.entities || []).filter(u=>shownIds.has(u));
    if (members.length < 2) continue;
    const entityByUid = new Map(shown.map(e=>[e.uid, e]));
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
      touched.add(hub); touched.add(u);
      spokes++;
    }
  }
  // Fallback anchor: ONLY for entities the loops above never touched at all —
  // unlike the ring layout (which anchored every node to the seed regardless,
  // then drew relation/correlation edges on top of that), a flow chart shows
  // exactly one "how did we get here" line per node when a real one exists,
  // and falls back to "found via the seed" only when nothing more specific do.
  for (const e of shown){
    if (touched.has(e.uid)) continue;
    if (links.length >= GRAPH_MAX_LINKS) break;
    links.push({source:seedId, target:e.uid, corr:false});
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

  // Resolve endpoints to node objects and drop links to unknown nodes.
  const nodesById = new Map(nodes.map(n=>[n.id, n]));
  const validLinks = links
    .filter(l=>nodesById.has(l.source) && nodesById.has(l.target))
    .map(l=>({...l, source: nodesById.get(l.source), target: nodesById.get(l.target)}));

  layoutFlowchart(nodes, W);

  // ── Draw: edges first so boxes sit above them ──
  const linkG = svgEl('g');
  container.appendChild(linkG);
  for (const l of validLinks){
    const line = svgEl('line', {
      x1: l.source.x, y1: l.source.y, x2: l.target.x, y2: l.target.y,
      stroke: l.lineage ? '#d9822b' : (l.rel ? '#d9822b' : (l.corr ? '#9b1f9b' : seedEdge)),
      'stroke-opacity': l.rel ? 0.85 : (l.corr ? 0.7 : (dark ? 0.5 : 0.3)),
      'stroke-width': l.lineage ? 2 : (l.rel ? 1.6 : (l.corr ? 1.6 : 1)),
    });
    if (l.rel && !l.lineage) line.setAttribute('stroke-dasharray', '5,3');
    if (l.lineage) line.setAttribute('marker-end', 'url(#flow-arrow)');
    const title = svgEl('title');
    title.textContent = l.rel ? ('relation: ' + l.kind) : (l.corr ? 'correlation' : 'found via the seed');
    line.appendChild(title);
    linkG.appendChild(line);
  }

  const nodeLayer = svgEl('g');
  container.appendChild(nodeLayer);
  for (const n of nodes){
    const g = svgEl('g', { transform: `translate(${n.x - n.w / 2},${n.y - n.h / 2})` });
    g.appendChild(svgEl('rect', {
      width: n.w, height: n.h, rx: 6, ry: 6,
      fill: n.isSeed ? '#059CD7' : (NODE_COLOR[n.kind] || '#888'),
      stroke: n.isSeed ? seedHalo : boxHalo,
      'stroke-width': n.isSeed ? 2 : 1.5,
    }));
    const t = svgEl('title');
    t.textContent = `${n.kind}: ${n.label}`;
    g.appendChild(t);
    const label = svgEl('text', {
      x: n.w / 2, y: n.h / 2 + 4, 'text-anchor': 'middle',
      'font-size': '11px', fill: n.isSeed ? '#fff' : labelFill,
    });
    const maxChars = Math.floor(n.w / 6.5);
    const l = n.label || '';
    label.textContent = l.length > maxChars ? l.slice(0, maxChars - 1) + '…' : l;
    g.appendChild(label);
    nodeLayer.appendChild(g);
  }

  // ── Pan / zoom, via pointer events (touch + mouse, no library) ──
  // `view` is module-scoped (see its declaration): the operator's pan and zoom
  // survive a rebuild, and are re-applied at the end of this function. Node
  // dragging is gone — a flow chart's box positions ARE the structure (row =
  // generation, rank = significance), so there is nothing left to drag.
  const applyView = ()=>container.setAttribute('transform', `translate(${view.x},${view.y}) scale(${view.k})`);
  const toViewBox = (clientX, clientY)=>{
    const b = svg.getBoundingClientRect();
    return {
      x: (clientX - b.left) * (W / (b.width || W)),
      y: (clientY - b.top) * (H / (b.height || H)),
    };
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

  const pointers = new Map(); // pointerId -> {clientX, clientY}
  let panFrom = null;         // {x, y} viewBox coords at pan start
  let pinchDist = 0;

  svg.addEventListener('pointerdown', (ev)=>{
    pointers.set(ev.pointerId, { clientX: ev.clientX, clientY: ev.clientY });
    if (pointers.size === 2){
      const [a, b] = Array.from(pointers.values());
      pinchDist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      panFrom = null;
    } else {
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
    if (panFrom){
      const p = toViewBox(ev.clientX, ev.clientY);
      view.x = p.x - panFrom.x;
      view.y = p.y - panFrom.y;
      applyView();
    }
  });

  const endPointer = (ev)=>{
    pointers.delete(ev.pointerId);
    if (pointers.size < 2) pinchDist = 0;
    if (pointers.size === 0) panFrom = null;
  };
  svg.addEventListener('pointerup', endPointer);
  svg.addEventListener('pointercancel', endPointer);

  applyView();
}
