import { $ } from '/static/js/helpers.js';
import { renderAudit } from '/static/js/scan_info/audit.js';
import { renderBenchmark } from '/static/js/scan_info/benchmark.js';
import { renderCommunities } from '/static/js/scan_info/communities.js';
import { renderCorrelations } from '/static/js/scan_info/correlations.js';
import { renderDuplicates } from '/static/js/scan_info/duplicates.js';
import { renderFindings } from '/static/js/scan_info/findings.js';
import { renderGaps } from '/static/js/scan_info/gaps.js';
import { renderIdentities } from '/static/js/scan_info/identities.js';
import { renderLeads } from '/static/js/scan_info/leads.js';
import { renderLocation } from '/static/js/scan_info/location.js';
import { renderMetrics } from '/static/js/scan_info/metrics.js';
import { renderNetwork } from '/static/js/scan_info/network.js';
import { renderPathTool } from '/static/js/scan_info/path.js';
import { renderPivots } from '/static/js/scan_info/pivots.js';
import { renderTimeline } from '/static/js/scan_info/timeline.js';
import { renderTrust } from '/static/js/scan_info/trust.js';

/* ── Report tab — the ONE digestible scan view. Stacks, in priority order, the
   subject's network (who/what the seed connects to), the recommended next
   pivots, cross-entity correlations, and the scored self-audit (incl. how much
   breach co-occurrence was quarantined out of the result). Consolidates what
   were ten tabs (Network / Leads / Status / Relations / Correlations / Audit /
   Settings) into one — the rest live under Browse / Graph / Scan Log. ── */
export async function renderReport(host, id, scan){
  host.innerHTML = `
    <div id="rpt-findings"></div>
    <div id="rpt-metrics" style="margin-top:18px"></div>
    <div id="rpt-network"  style="margin-top:18px"></div>
    <div id="rpt-identities" style="margin-top:18px"></div>
    <div id="rpt-location" style="margin-top:18px"></div>
    <div id="rpt-leads"    style="margin-top:18px"></div>
    <div id="rpt-timeline" style="margin-top:18px"></div>
    <div id="rpt-communities" style="margin-top:18px"></div>
    <div id="rpt-trust"    style="margin-top:18px"></div>
    <div id="rpt-pivots"   style="margin-top:18px"></div>
    <div id="rpt-gaps"     style="margin-top:18px"></div>
    <div id="rpt-path"     style="margin-top:18px"></div>
    <div id="rpt-duplicates" style="margin-top:18px"></div>
    <div id="rpt-benchmark" style="margin-top:18px"></div>
    <div id="rpt-corr"     style="margin-top:18px"></div>
    <div id="rpt-audit"    style="margin-top:18px"></div>`;
  // Each renderer owns its sub-section (and its own async fetch); composing them
  // reuses the synthesis already built rather than duplicating any logic.
  renderFindings($('#rpt-findings'), id);
  renderMetrics($('#rpt-metrics'), id);
  renderNetwork($('#rpt-network'), id);
  renderIdentities($('#rpt-identities'), id);
  renderLocation($('#rpt-location'), id);
  renderLeads($('#rpt-leads'), id);
  renderTimeline($('#rpt-timeline'), id);
  renderCommunities($('#rpt-communities'), id);
  renderTrust($('#rpt-trust'), id);
  renderPivots($('#rpt-pivots'), id);
  renderGaps($('#rpt-gaps'), id);
  renderPathTool($('#rpt-path'), id);
  renderDuplicates($('#rpt-duplicates'), id);
  renderBenchmark($('#rpt-benchmark'), id);
  renderCorrelations($('#rpt-corr'));
  renderAudit($('#rpt-audit'), id);
}

