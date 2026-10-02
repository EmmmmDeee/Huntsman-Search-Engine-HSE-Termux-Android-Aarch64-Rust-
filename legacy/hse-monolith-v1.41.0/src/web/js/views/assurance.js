import { API } from '/static/js/api.js';
import { $, esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ═══════════ Page: ASSURANCE (#/assurance[?profile=…]) ═══════════
 * BSI / IT-Grundschutz posture, derived from recorded evidence server-side
 * (src/core/assurance) and fetched from /api/v1/assurance — the same table
 * `hse assurance` / `hse bsi` print; the API computes nothing of its own.
 * Every control row is drillable: click it to see the evidence that earned its
 * state, kind by kind, with provenance. The only numbers are raw counts — no
 * decorative compliance score exists to show. */

const LEVEL_CODE = {Unknown:'A0', Defined:'A1', Implemented:'A2', Enforced:'A3', Tested:'A4', Observed:'A5', Assured:'A6'};
const PROFILES = ['core','development','android','ble','termux','web','storage','cloud','intelligence'];
const EVIDENCE_EARNS = {
  definition:'A1 Defined', implementation:'A2 Implemented', enforcement:'A3 Enforced',
  test:'A4 Tested', 'runtime-observation':'A5 Observed', 'external-assurance':'A6 Assured',
};

function stateCell(s){
  const cls = s==='NOT_APPLICABLE' ? 'text-muted'
            : (s==='REGRESSED'||s==='GAP'||s==='UNKNOWN') ? 'text-danger' : 'text-success';
  return `<span class="${cls}"><strong>${esc(s)}</strong></span>`;
}
function sevCell(sev){
  if (!sev) return '<span class="text-muted">—</span>';
  const cls = (sev==='critical'||sev==='high') ? 'label-danger' : sev==='medium' ? 'label-warning' : 'label-default';
  return `<span class="label ${cls}">${esc(sev.toUpperCase())}</span>`;
}
function stat(label, val, color){
  return `<div class="col-sm-2"><div class="stat-card"><div class="lab">${esc(label)}</div><div class="val"${color?` style="color:${color}"`:''}>${esc(val==null?'—':val)}</div></div></div>`;
}

/* The drill-down row beneath a control: its requirement, scope and every
 * evidence record with the rung it earns and its provenance. */
function evidenceRow(c){
  const ev = c.evidence || [];
  const scope = `${esc(c.framework)} ${esc(c.framework_version)} · ${esc(c.applicability)}${c.applicability_reason ? ': ' + esc(c.applicability_reason) : ''}`;
  const body = ev.length
    ? `<table class="table table-condensed" style="margin:0;font-size:11px">
         <thead><tr><th style="width:150px">Evidence kind</th><th style="width:130px">Earns</th><th>Source (provenance)</th><th>Detail</th></tr></thead>
         <tbody>${ev.map(e=>`<tr><td><code>${esc(e.kind)}</code></td><td>${esc(EVIDENCE_EARNS[e.kind]||'')}</td><td><code>${esc(e.source)}</code></td><td>${esc(e.detail)}</td></tr>`).join('')}</tbody>
       </table>`
    : '<div class="text-muted" style="font-size:11px">No evidence recorded — this control holds nothing above A0.</div>';
  return `<tr class="asr-ev"><td colspan="7" style="background:#fafafa;padding:6px 12px">
    <div style="font-size:11px;margin-bottom:4px"><strong>Requirement:</strong> ${esc(c.requirement)} <span class="text-muted">(${scope})</span></div>
    ${body}
  </td></tr>`;
}
function controlRows(r, i){
  const c = r.control;
  return `<tr class="asr-row" data-i="${i}" style="cursor:pointer" title="Click for the evidence behind this state">
      <td><code>${esc(c.id)}</code></td><td>${esc(c.module)}</td><td>${stateCell(r.state)}</td>
      <td>${esc(LEVEL_CODE[r.level]||r.level)}</td><td>${sevCell(r.severity)}</td>
      <td>${esc(c.profile)}</td><td>${esc(c.criticality)}</td>
    </tr>` + evidenceRow(c);
}
function verdictBanner(vd){
  const ok = !!vd.ok;
  const reasons = [];
  if ((vd.regressions||[]).length) reasons.push(`${vd.regressions.length} regressed: ${vd.regressions.map(f=>f.control_id).join(', ')}`);
  if ((vd.blocking||[]).length)    reasons.push(`${vd.blocking.length} High/Critical open: ${vd.blocking.map(f=>f.control_id).join(', ')}`);
  const warn = (vd.warnings||[]).length;
  return `<div class="alert ${ok?'alert-success':'alert-danger'}" style="margin-bottom:14px">
    <strong>hse bsi verify: ${ok?'PASS':'FAIL'}.</strong>
    ${ok ? 'No control has regressed and no High/Critical deficiency is open.' : esc(reasons.join(' · '))}
    ${warn ? `<span class="text-muted"> · ${warn} advisory (Low/Medium) gap${warn===1?'':'s'}, non-failing.</span>` : ''}
  </div>`;
}

/* BSI 200-4 continuity: one row per capability, worst-first, with the derived
 * state (UNTESTED / TESTED / OBSERVED), the objectives a test actually asserts,
 * and the recovery tests that are its evidence. Untested capabilities are
 * named in the heading, never folded into a percentage. */
function contState(s){
  const cls = s==='UNTESTED' ? 'label-danger' : 'label-success';
  return `<span class="label ${cls}">${esc(s)}</span>`;
}
function continuityPanel(caps, s){
  const gaps = (s.untested_capabilities||[]);
  const head = `Continuity (BSI 200-4) <small class="text-muted">— ${s.tested||0} tested · ${s.untested||0} untested · ${s.observed||0} observed${gaps.length ? ' · untested: ' + esc(gaps.join(', ')) : ''}</small>`;
  const rows = caps.map(c=>{ const o=c.objective||{}; return `<tr>
      <td><code>${esc(o.capability)}</code><div class="text-muted" style="font-size:10px">${esc(o.name)}</div></td>
      <td>${esc(o.criticality)}</td><td>${contState(c.state)}</td>
      <td>${o.rto_secs!=null ? esc(o.rto_secs)+' s' : '<span class="text-muted">unasserted</span>'}</td>
      <td>${esc(o.rpo_label || o.rpo)}</td>
      <td style="font-size:11px">${(o.recovery_tests||[]).length ? o.recovery_tests.map(t=>`<code>${esc(t)}</code>`).join('<br>') : '<span class="text-danger">none — unproven by any test</span>'}</td>
      <td style="font-size:11px">${esc(o.degraded_mode)}</td>
    </tr>`; }).join('');
  return `<div class="panel panel-default">
      <div class="panel-heading">${head}</div>
      <table class="table table-condensed" style="margin:0">
        <thead><tr><th>Capability</th><th>Criticality</th><th>State</th><th>RTO</th><th>RPO</th><th>Recovery tests (evidence)</th><th>Degraded mode</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

export async function renderAssurance(v){
  const profile = (S.route && S.route.query && S.route.query.profile) || '';
  const [data, vf, ct] = await Promise.all([API.assurance(profile), API.assuranceVerify(), API.assuranceContinuity()]);
  const controls = data.controls || [], findings = data.findings || [], s = data.summary || {};
  const vd = vf.verdict || {};
  const caps = ct.capabilities || [], cs = ct.summary || {};

  const opts = ['<option value="">All profiles</option>']
    .concat(PROFILES.map(p=>`<option value="${p}"${p===profile?' selected':''}>${esc(p)}</option>`)).join('');

  v.innerHTML = `
    <h2>BSI Assurance &nbsp;<small class="text-muted">evidence-derived control status${data.profile ? ' · ' + esc(data.profile) : ''}</small>
      <div class="pull-right">
        <select id="asr-profile" class="form-control input-sm" style="display:inline-block;width:auto;margin-right:6px">${opts}</select>
        <a class="btn btn-default btn-sm" href="#/attack" title="MITRE ATT&amp;CK posture"><i class="glyphicon glyphicon-eye-open"></i>&nbsp;ATT&amp;CK</a>
        <button class="btn btn-default btn-sm" onclick="render()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
      </div>
    </h2>
    <hr style="margin:8px 0 14px 0">
    ${verdictBanner(vd)}

    <div class="row">
      ${stat('Controls', s.total)}
      ${stat('Out of scope', s.not_applicable, '#888')}
      ${stat('Deficiencies', s.deficiencies, s.deficiencies ? '#a94442' : '#3c763d')}
      ${stat('Critical / High', `${s.critical_findings||0} / ${s.high_findings||0}`, (s.critical_findings||s.high_findings) ? '#a94442' : '#888')}
      ${stat('Tested+ (A4+)', s.tested_or_higher)}
      ${stat('Observed+ (A5+)', s.observed_or_higher)}
    </div>

    ${findings.length ? `
    <div class="panel panel-danger">
      <div class="panel-heading">Open findings <small>— graded from criticality and Schutzbedarf, worst first</small></div>
      <table class="table table-condensed" style="margin:0">
        <thead><tr><th>Control</th><th>Module</th><th>State</th><th>Severity</th><th>Criticality</th></tr></thead>
        <tbody>${findings.map(f=>`<tr><td><code>${esc(f.control_id)}</code></td><td>${esc(f.module)}</td><td>${stateCell(f.state)}</td><td>${sevCell(f.severity)}</td><td>${esc(f.criticality)}</td></tr>`).join('')}</tbody>
      </table>
    </div>` : ''}

    ${continuityPanel(caps, cs)}

    <div class="panel panel-default">
      <div class="panel-heading">Controls <small class="text-muted">— click a row for the evidence that earned its state</small></div>
      <table class="table table-condensed table-hover" style="margin:0" id="asr-table">
        <thead><tr><th>Control</th><th>Module</th><th>State</th><th>Level</th><th>Severity</th><th>Profile</th><th>Criticality</th></tr></thead>
        <tbody>${controls.map(controlRows).join('')}</tbody>
      </table>
    </div>

    <p class="text-muted" style="font-size:11px">Maturity is derived from recorded evidence, never asserted: a catalogued framework mapping earns only A1; A5/A6 need runtime-observation / independent-assurance evidence. NOT_APPLICABLE is out of scope, not a failure. No certification or compliance claim is made.</p>
  `;

  // Evidence drill-down: detail rows start hidden; clicking a control toggles its own.
  document.querySelectorAll('#asr-table tr.asr-ev').forEach(tr=>{ tr.style.display = 'none'; });
  document.querySelectorAll('#asr-table tr.asr-row').forEach(tr=>{
    tr.addEventListener('click', ()=>{
      const d = tr.nextElementSibling;
      if (d) d.style.display = d.style.display === 'none' ? '' : 'none';
    });
  });
  $('#asr-profile').addEventListener('change', e=>{
    location.hash = '#/assurance' + (e.target.value ? `?profile=${encodeURIComponent(e.target.value)}` : '');
  });
}
