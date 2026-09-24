import { API } from '/static/js/api.js';
import { $, esc } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { renderBrowseTableHtml } from '/static/hse_wasm_ui.js';
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

/* The page's own search box, in the input-group-with-button form SpiderFoot
 * uses for its in-scan search. The navbar carries no search field (SpiderFoot
 * 4.0's has none), so this is where a cross-scan search starts; `#global-q`
 * is the field `globalSearch` reads. */
function searchForm(q){
  return `<form role="search" onsubmit="globalSearch(event)" style="margin:0 0 15px">
    <div class="input-group">
      <input type="search" id="global-q" class="form-control" value="${esc(q)}" maxlength="256"
             placeholder="Search every entity in every scan…" aria-label="Search all entities"
             autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
      <span class="input-group-btn">
        <button class="btn btn-primary" type="submit" title="Search"><i class="glyphicon glyphicon-search" aria-hidden="true"></i>&nbsp;Search</button>
      </span>
    </div>
  </form>`;
}

/* ═══════════ Page: GLOBAL SEARCH (#/search?q=…) — FTS5-backed ═══════════ */
export async function renderSearch(v){
  const q = (S.route.query.q||'').trim();
  if (q.length < 2){
    v.innerHTML = `<h2>Search All Scans</h2>
      ${searchForm(q)}
      <div class="alert alert-info">Type at least 2 characters. Matching is tokenized,
      word-order-independent and relevance-ranked (SQLite FTS5) across every scan.</div>`;
    $('#global-q')?.focus();
    return;
  }
  // A refused query stays on this page, beside the box that can fix it. Left
  // to render()'s error page, it would offer only a Retry of the same query,
  // with no box: this page holds the console's only search field. (The API
  // caps a query at 256 bytes, so a long non-ASCII one can pass the box's
  // 256-character limit and still be refused.)
  let data;
  try { data = await API.search(q, 200); }
  catch (e){
    v.innerHTML = `<h2>Search All Scans</h2>
      ${searchForm(q)}
      <div class="alert alert-danger">${esc(e.message)}</div>`;
    $('#global-q')?.focus();
    return;
  }
  const rows = data.entities || [];
  v.innerHTML = `
    <h2>Search All Scans
      <small>${rows.length} match${rows.length===1?'':'es'} for <code>${esc(q)}</code></small>
    </h2>
    ${searchForm(q)}
    ${renderBrowseTableHtml(rows,
      { entities_total: S.entitiesTotal ?? null, loaded_count: S.entities ? S.entities.length : null })}`;
  if (window.jQuery && jQuery.fn.tablesorter && rows.length){
    try { jQuery('#browse-table').tablesorter(); } catch(_){}
  }
}

