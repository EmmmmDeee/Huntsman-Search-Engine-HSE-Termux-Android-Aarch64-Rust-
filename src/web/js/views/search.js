import { API } from '/static/js/api.js';
import { $, esc } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { renderBrowseTable } from '/static/js/scan_info/browse.js';
import { S } from '/static/js/state.js';

export function globalSearch(e){
  e.preventDefault();
  const q = (($('#global-q')||{}).value || '').trim();
  if (q.length < 2){
    if (typeof alertify !== 'undefined') alertify.warning('Enter at least 2 characters to search');
    return;
  }
  // Navigate to a real route so the result survives render()'s hash re-parse
  // (the old code hand-mutated S.route, which render() immediately overwrote).
  nav('#/search?q='+encodeURIComponent(q));
}

/* ═══════════ Page: GLOBAL SEARCH (#/search?q=…) — FTS5-backed ═══════════ */
export async function renderSearch(v){
  const q = (S.route.query.q||'').trim();
  if (q.length < 2){
    v.innerHTML = '<div class="empty-state"><h3>Search all entities</h3>'
      + '<p>Type at least 2 characters in the search box above. Matching is tokenized, '
      + 'word-order-independent and relevance-ranked (SQLite FTS5) across every scan.</p></div>';
    return;
  }
  const data = await API.search(q, 200);
  const rows = data.entities || [];
  v.innerHTML = `
    <div class="page-header" style="margin-top:0;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-search"></i>&nbsp;Search results
        <small>${rows.length} match${rows.length===1?'':'es'} for <code>${esc(q)}</code> across all scans</small>
      </h3>
    </div>
    ${renderBrowseTable(rows)}`;
  if (window.jQuery && jQuery.fn.tablesorter && rows.length){
    try { jQuery('#browse-table').tablesorter(); } catch(_){}
  }
}

