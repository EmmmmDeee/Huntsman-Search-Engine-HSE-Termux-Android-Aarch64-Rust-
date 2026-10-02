import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';

/* ═══════════ Page: ATT&CK (#/attack) ═══════════
 * MITRE ATT&CK posture over HSE's versioned core::attack layer — the same data
 * `hse attack {status,coverage,gaps,navigator}` prints, fetched from
 * /api/v1/attack (which computes nothing of its own). HSE is a passive,
 * authorised OSINT collector, so it honestly claims ONE tactic — Reconnaissance
 * (TA0043). Every covered technique lists the registered modules that are its
 * evidence; the gaps are the honest uncovered slice. This is collection reach,
 * not detection effectiveness, and no decorative score is shown. */

function moduleCell(mods){
  if (mods && mods.length) return mods.map(m=>`<code>${esc(m)}</code>`).join(' ');
  return '<span class="text-muted">— entity/relation mapping</span>';
}

export async function renderAttack(v){
  const d = await API.attack();
  const covered = d.covered || [], gaps = d.gaps || [];
  const pct = Math.round((d.coverage_fraction||0)*1000)/10;

  v.innerHTML = `
    <h2>MITRE ATT&amp;CK &nbsp;<small class="text-muted">Enterprise v${esc(d.attack_version)} · ${esc(d.tactic_id)} ${esc(d.tactic_name)}</small>
      <div class="pull-right">
        <a class="btn btn-default btn-sm" href="/api/v1/attack/navigator" download="hse-attack-navigator.json"
           title="Import into the official ATT&amp;CK Navigator"><i class="glyphicon glyphicon-download-alt"></i>&nbsp;Navigator layer</a>
        <button class="btn btn-default btn-sm" onclick="render()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
      </div>
    </h2>
    <hr style="margin:8px 0 14px 0">

    <div class="row">
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Tactic in scope</div><div class="val" style="font-size:16px">${esc(d.tactic_name)}</div><div class="text-muted" style="font-size:10px">the one tactic HSE performs collection for</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Techniques covered</div><div class="val">${d.techniques_covered}/${d.techniques_total}</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Coverage</div><div class="val">${pct}%</div><div class="text-muted" style="font-size:10px">derived from real module capability</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Honest gaps</div><div class="val" style="color:${gaps.length?'#8a6d3b':'#3c763d'}">${gaps.length}</div></div></div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">Reconnaissance coverage <small class="text-muted">— each technique and the modules that are its evidence</small></div>
      <table class="table table-condensed table-hover" style="margin:0">
        <thead><tr><th style="width:110px">Technique</th><th style="width:260px">Name</th><th>Modules (evidence)</th></tr></thead>
        <tbody>${covered.map(c=>`<tr><td><code>${esc(c.id)}</code></td><td>${esc(c.name)}</td><td style="font-size:11px">${moduleCell(c.modules)}</td></tr>`).join('')}</tbody>
      </table>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">Coverage gaps <small class="text-muted">— catalogued Reconnaissance techniques no module collects for</small></div>
      ${gaps.length
        ? `<table class="table table-condensed" style="margin:0"><thead><tr><th style="width:110px">Technique</th><th>Name</th></tr></thead><tbody>${gaps.map(g=>`<tr><td><code>${esc(g.id)}</code></td><td>${esc(g.name)}</td></tr>`).join('')}</tbody></table>`
        : '<div class="panel-body text-muted">No gaps: every catalogued Reconnaissance technique is covered.</div>'}
    </div>

    <p class="text-muted" style="font-size:11px">ATT&amp;CK coverage ≠ detection effectiveness: this reports collection reach for TA0043 only. No other tactic is claimed and no decorative score is emitted.</p>
  `;
}
