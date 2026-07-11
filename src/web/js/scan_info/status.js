import { attr, effC, esc, kindPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Status tab ── */
export function renderStatus(host, scan){
  const byKind = new Map();
  for (const e of S.entities) byKind.set(e.kind, (byKind.get(e.kind)||0) + 1);
  const kindSorted = Array.from(byKind.entries()).sort((a,b)=>b[1]-a[1]);
  const kindMax = kindSorted.length ? kindSorted[0][1] : 1;  // scale bars to the largest type
  const kindRows = kindSorted.map(([k,n])=>{
    const share = ((n/Math.max(1,S.entities.length))*100).toFixed(0);
    const barW = ((n/Math.max(1,kindMax))*100).toFixed(1);
    return `<tr><td>${kindPill(k)}</td><td class="text-right">${n}</td>
         <td class="kbar-cell"><div class="kbar-track"><div class="kbar-fill" style="width:${barW}%"></div><span class="kbar-pct">${share}%</span></div></td></tr>`;
  }).join('');

  const byMod = new Map();
  for (const e of S.entities) for (const ev of (e.evidence||[])) byMod.set(ev.source, (byMod.get(ev.source)||0)+1);
  const modRows = Array.from(byMod.entries()).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([m,n])=>
    `<tr><td><code>${esc(m)}</code></td><td class="text-right">${n}</td></tr>`).join('');

  let verified=0, probable=0, candidate=0;
  for (const e of S.entities){
    const eff = effC(e);
    if (eff>=0.75) verified++; else if (eff>=0.40) probable++; else candidate++;
  }

  host.innerHTML = `
    <div class="row">
      <div class="col-sm-6">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Entities by type</b></div>
          ${kindRows
            ? `<table class="table table-striped table-condensed" style="margin-bottom:0">
                 <thead><tr><th>Type</th><th class="text-right">Count</th><th>Share</th></tr></thead>
                 <tbody>${kindRows}</tbody></table>`
            : '<div class="empty-state"><p>No entities yet.</p></div>'}
        </div>
      </div>
      <div class="col-sm-6">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Classification</b></div>
          <div class="panel-body">
            <div class="row text-center">
              <div class="col-xs-4"><div class="stat-card"><div class="lab c-VERIFIED">Verified</div><div class="val" style="color:#3c763d">${verified}</div></div></div>
              <div class="col-xs-4"><div class="stat-card"><div class="lab c-PROBABLE">Probable</div><div class="val" style="color:#8a6d3b">${probable}</div></div></div>
              <div class="col-xs-4"><div class="stat-card"><div class="lab c-CANDIDATE">Candidate</div><div class="val" style="color:#a94442">${candidate}</div></div></div>
            </div>
            <p class="help-block">Tiers derived from <code>C_eff = clamp(C × (1 + 0.15·ln(distinct_sources)), 0, 1)</code>.</p>
          </div>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-sm-6">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Top contributing modules</b></div>
          ${modRows
            ? `<table class="table table-striped table-condensed" style="margin-bottom:0">
                 <thead><tr><th>Module</th><th class="text-right">Evidence rows</th></tr></thead>
                 <tbody>${modRows}</tbody></table>`
            : '<div class="empty-state"><p>No evidence yet.</p></div>'}
        </div>
      </div>
      <div class="col-sm-6">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Correlation summary</b></div>
          <div class="panel-body">
            ${S.correlations.length
              ? `Click <a href="#/scaninfo?id=${attr(S.route.params.id)}&tab=corr">Correlations</a> for the full list. Severity breakdown:
                 <div style="margin-top:8px">
                   ${['critical','high','medium','low'].map(sev=>{
                     const n = S.correlations.filter(c=>(c.severity||'').toLowerCase()===sev).length;
                     return `<span class="status-pill sev-count">${esc(sev)}: ${n}</span>`;
                   }).join('')}
                 </div>`
              : '<div class="empty-state"><p>No correlation rules have fired for this scan.</p></div>'}
          </div>
        </div>
      </div>
    </div>
  `;
}

