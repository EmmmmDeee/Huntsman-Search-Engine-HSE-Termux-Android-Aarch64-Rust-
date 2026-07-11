import { API } from '/static/js/api.js';
import { esc, kindPill } from '/static/js/helpers.js';

/* ── Audit tab — scored self-audit (GET /scans/{id}/audit) ── */
export function auditScoreColor(s){ return s>=90?'#3c763d' : s>=75?'#5cb85c' : s>=60?'#8a6d3b' : s>=40?'#d9534f' : '#a94442'; }
export function sevBadge(sev){
  const c = sev==='CRITICAL'?'#a94442' : sev==='HIGH'?'#d9534f' : sev==='MEDIUM'?'#8a6d3b' : sev==='LOW'?'#777' : '#999';
  return `<span style="display:inline-block;min-width:64px;text-align:center;color:#fff;background:${c};border-radius:3px;font-size:11px;font-weight:600;padding:1px 6px">${esc(sev)}</span>`;
}
export async function renderAudit(host, id){
  host.innerHTML = '<p class="text-muted">Auditing scan…</p>';
  let r;
  try { r = await API.auditScan(id); }
  catch(e){ host.innerHTML = `<div class="empty-state"><h3>Audit unavailable</h3><p>${esc(e.message)}</p></div>`; return; }
  const col = auditScoreColor(r.score);
  const kinds = Object.entries(r.by_kind||{}).sort((a,b)=>b[1]-a[1])
    .map(([k,n])=>`${kindPill(k)}&nbsp;${n}`).join('&nbsp; ');
  const findings = (r.findings||[]).map(f=>{
    const ex = (f.examples||[]).map(x=>`<li><code>${esc(x)}</code></li>`).join('');
    return `<div style="border-left:4px solid ${col===''?'#ccc':'#ddd'};border-left-color:${
      f.severity==='CRITICAL'||f.severity==='HIGH'?'#d9534f':'#8a6d3b'};
      background:#fafafa;padding:10px 12px;margin-bottom:10px;border-radius:3px">
      <div>${sevBadge(f.severity)}&nbsp;<b>${esc(f.category)}</b></div>
      <div style="margin:6px 0">${esc(f.message)}</div>
      ${ex?`<ul style="margin:4px 0 6px 18px;color:#555">${ex}</ul>`:''}
      <div style="color:#3c763d"><i class="glyphicon glyphicon-arrow-right"></i>&nbsp;${esc(f.recommendation)}</div>
    </div>`;
  }).join('');
  const sh = r.source_health||{};
  const shBits = [];
  if ((sh.engine_parser_defects||[]).length) shBits.push(`parser-defect: ${sh.engine_parser_defects.map(esc).join(', ')}`);
  if ((sh.engines_down||[]).length) shBits.push(`down: ${sh.engines_down.map(esc).join(', ')}`);
  if ((sh.engines_blocked||[]).length) shBits.push(`blocked: ${sh.engines_blocked.map(esc).join(', ')}`);
  const me = sh.module_errors||{}; const meKeys = Object.keys(me);
  if (meKeys.length) shBits.push(`module errors: ${meKeys.map(k=>esc(k)+'×'+me[k]).join(', ')}`);
  // HTTP transport failures during the scan — a reliability signal the API has
  // always computed (source_health.http_failures) but the panel never showed.
  if (sh.http_failures) shBits.push(`HTTP failures: ${sh.http_failures}`);
  // Expansion ledger: every pivot the recursion declined to follow, by reason —
  // makes the recursion non-black-box. identity_mismatch is the recall-relevant
  // one (lift with --expand-all-identities); the rest are expected hygiene.
  const exp = r.expansion||{};
  const exr = exp.excluded_reasons||{}; const exrKeys = Object.keys(exr);
  const exBits = exrKeys.map(k=>esc(k)+'×'+exr[k]);
  if ((exp.stops||[]).length) exBits.push('stops: '+exp.stops.map(esc).join(', '));
  host.innerHTML = `
    <div class="row">
      <div class="col-sm-3 col-xs-6"><div class="stat-card"><div class="lab">Quality score</div>
        <div class="val" style="color:${col}">${r.score}<span style="font-size:14px;color:#999">/100</span></div></div></div>
      <div class="col-sm-9 col-xs-6"><div class="stat-card" style="text-align:left">
        <div class="lab">Grade</div><div style="font-size:15px;color:${col};font-weight:600">${esc(r.grade||'')}</div>
        <div class="text-muted" style="margin-top:4px">${r.entity_total} entities · ${r.tiers.verified} verified · ${r.tiers.probable} probable · ${r.tiers.candidate} candidate · ${Math.round((r.noise_ratio||0)*100)}% noise${r.quarantined?` · <span style="color:#8a6d3b">${r.quarantined} quarantined</span>`:''}</div>
        ${(r.geo&&r.geo.coord_count)?`<div class="text-muted" style="margin-top:2px">geo: ${r.geo.coord_count} fix(es) / ${r.geo.source_count} source(s) · spread ${Math.round(r.geo.max_spread_km)} km · ${r.geo.has_consensus?'consensus':'no consensus'}${r.geo.outliers?` · <span style="color:#d9534f">${r.geo.outliers} outlier(s)</span>`:''}</div>`:''}
      </div></div>
    </div>
    ${kinds?`<p class="text-muted" style="margin:6px 0 12px">${kinds}</p>`:''}
    ${shBits.length?`<div class="alert alert-warning" style="padding:8px 12px"><b>Source health:</b> ${shBits.join(' · ')}</div>`:''}
    ${exBits.length?`<div class="alert alert-info" style="padding:8px 12px"><b>Expansion ledger:</b> ${exBits.join(' · ')}</div>`:''}
    <h4 style="margin-top:6px">Findings ${r.findings.length?`<span class="badge">${r.findings.length}</span>`:''}</h4>
    ${findings || '<div class="alert alert-success">✓ No weaknesses detected — results are individualised and verifiable.</div>'}
    <p class="text-muted" style="font-size:12px;margin-top:10px">${sh.log_lines_parsed?`Audited ${sh.log_lines_parsed} scan-log line(s). `:''}Same audit as <code>hse audit --scan-id ${esc(id)}</code>. Re-run after fixes to confirm the score improves.</p>`;
}

