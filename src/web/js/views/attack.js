import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';

/* ═══════════ Page: ATT&CK (#/attack) ═══════════
 * MITRE ATT&CK posture over HSE's versioned core::attack layer. The scored
 * denominator is hierarchy-aware: sub-techniques are independent leaves, while
 * a parent with children is a roll-up and is not counted again. Raw direct
 * parent/sub-technique claims remain visible for provenance and Navigator export.
 * This is collection reach, not detection effectiveness. */

function moduleCell(mods){
  if (mods && mods.length) return mods.map(m=>`<code>${esc(m)}</code>`).join(' ');
  return '<span class="text-muted">— entity/relation mapping</span>';
}

function techniqueTable(rows, emptyText){
  if (!rows.length) return `<div class="panel-body text-muted">${esc(emptyText)}</div>`;
  return `<table class="table table-condensed" style="margin:0">
    <thead><tr><th style="width:110px">Technique</th><th>Name</th></tr></thead>
    <tbody>${rows.map(row=>`<tr><td><code>${esc(row.id)}</code></td><td>${esc(row.name)}</td></tr>`).join('')}</tbody>
  </table>`;
}

export async function renderAttack(v){
  const d = await API.attack();
  const covered = d.covered || [];
  const capabilityGaps = d.capability_gaps || [];
  const exclusions = d.intentional_exclusions || [];
  const parents = d.parent_rollups || [];
  const pct = Math.round((d.coverage_fraction||0)*1000)/10;

  v.innerHTML = `
    <h2>MITRE ATT&amp;CK &nbsp;<small class="text-muted">Enterprise v${esc(d.attack_version)} · ${esc(d.tactic_id)} ${esc(d.tactic_name)}</small>
      <div class="pull-right">
        <a class="btn btn-default btn-sm" href="/api/v1/attack/navigator" download="hse-attack-navigator.json"
           title="Import raw ATT&amp;CK claims into the official Navigator"><i class="glyphicon glyphicon-download-alt"></i>&nbsp;Navigator layer</a>
        <button class="btn btn-default btn-sm" onclick="render()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
      </div>
    </h2>
    <hr style="margin:8px 0 14px 0">

    <div class="row">
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Tactic in scope</div><div class="val" style="font-size:16px">${esc(d.tactic_name)}</div><div class="text-muted" style="font-size:10px">the one tactic HSE performs collection for</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Leaf capabilities</div><div class="val">${d.leaf_techniques_covered}/${d.leaf_techniques_total}</div><div class="text-muted" style="font-size:10px">${pct}% · parents are roll-ups, not extra units</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Capability gaps</div><div class="val" style="color:${capabilityGaps.length?'#8a6d3b':'#3c763d'}">${capabilityGaps.length}</div><div class="text-muted" style="font-size:10px">material collection capability not implemented</div></div></div>
      <div class="col-sm-3"><div class="stat-card"><div class="lab">Excluded by design</div><div class="val">${exclusions.length}</div><div class="text-muted" style="font-size:10px">outside HSE's collection contract</div></div></div>
    </div>

    <p class="text-muted" style="font-size:11px;margin:4px 0 12px 0">
      Raw provenance: <strong>${d.attack_objects_covered}/${d.attack_objects_total}</strong> ATT&amp;CK objects directly claimed (parents + sub-techniques). Those object counts are retained for attribution and Navigator export but are not the scored denominator.
    </p>

    <div class="panel panel-default">
      <div class="panel-heading">Covered leaf capabilities <small class="text-muted">— independent collection capabilities and the modules that are their evidence</small></div>
      <table class="table table-condensed table-hover" style="margin:0">
        <thead><tr><th style="width:110px">Technique</th><th style="width:260px">Name</th><th>Modules (evidence)</th></tr></thead>
        <tbody>${covered.map(c=>`<tr><td><code>${esc(c.id)}</code></td><td>${esc(c.name)}</td><td style="font-size:11px">${moduleCell(c.modules)}</td></tr>`).join('')}</tbody>
      </table>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">Parent-family roll-ups <small class="text-muted">— informational only; parents with children do not add another scored unit</small></div>
      <table class="table table-condensed" style="margin:0">
        <thead><tr><th style="width:110px">Parent</th><th>Name</th><th style="width:130px">Children</th><th style="width:150px">Direct parent claim</th></tr></thead>
        <tbody>${parents.map(p=>`<tr><td><code>${esc(p.id)}</code></td><td>${esc(p.name)}</td><td>${p.covered_children}/${p.total_children}</td><td>${p.directly_covered?'yes':'no'}</td></tr>`).join('')}</tbody>
      </table>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">Capability gaps <small class="text-muted">— uncovered leaves where additional collection capability would close a real gap</small></div>
      ${techniqueTable(capabilityGaps, 'No material leaf-capability gaps.')}
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">Intentional exclusions <small class="text-muted">— catalogued Reconnaissance leaves deliberately outside HSE's collection contract</small></div>
      ${techniqueTable(exclusions, 'No intentional exclusions.')}
    </div>

    <p class="text-muted" style="font-size:11px">ATT&amp;CK coverage ≠ detection effectiveness. The ${pct}% figure is leaf-capability collection reach for TA0043 only; raw ATT&amp;CK object claims remain separately visible and no other tactic is claimed.</p>
  `;
}
