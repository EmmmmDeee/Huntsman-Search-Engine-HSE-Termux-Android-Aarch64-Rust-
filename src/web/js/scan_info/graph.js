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

  // Build nodes/edges.
  const seedId = '__seed__';
  const nodes = [{id:seedId, kind:S.scan.target.kind, label:S.scan.target.value, isSeed:true, r:12}];
  for (const e of S.entities){
    nodes.push({id:e.uid, kind:e.kind, label:e.value, r: 5 + Math.min(8, Math.log(1+(e.corroboration||1))*3)});
  }
  const links = [];
  for (const e of S.entities) links.push({source:seedId, target:e.uid, corr:false});
  for (const c of S.correlations){
    const uids = c.entity_uids || c.evidence_uids || c.entities || [];
    for (let i=0;i<uids.length;i++) for (let j=i+1;j<uids.length;j++)
      links.push({source:uids[i], target:uids[j], corr:true});
  }
  // Typed attribution edges (subdomain_of / belongs_to_domain / hosted_on /
  // derived_from / co_located_with) between entity nodes.
  for (const r of (S.relations||[]))
    links.push({source:r.from_uid, target:r.to_uid, rel:true, kind:r.kind});

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

