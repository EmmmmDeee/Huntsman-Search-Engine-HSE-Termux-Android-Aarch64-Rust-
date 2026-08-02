import { $, $$, attr, esc, toast, triggerBlobDownload } from '/static/js/helpers.js';
import { API } from '/static/js/api.js';

// A stealer-log import can carry tens of thousands of rows (the importer caps a
// dump at 500 victims × 200 creds = up to 100k). Rendering them all builds one
// giant <table>/<pre> with ~5 event listeners per <tr> in a single synchronous
// pass — and the search box re-ran that on EVERY keystroke — which freezes the
// tab on a 2-core Termux phone. Cap what is *rendered* (copy/download/export
// still act on the full matching set) and debounce the search.
const STEALER_ROW_CAP = 1000;
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ── Stealer Logs Viewer — file-explorer refactor ────────────────────────
   Paired login+password+domain+capture-date credential rows from a stealer-
   log import, powered by /scans/{id}/stealer-rows. The generic entity graph
   (the Browse tab) intentionally flattens a credential's login and password
   into separate, unlinked entities so they merge/correlate like any other
   finding — this tab is the paired, file-explorer-style complement.

   Tree taxonomy: Import ▸ Machine (log_id) ▸ {Passwords.txt, Combos.txt}
   (site-keyed vs. raw-pair, per StealerRowKind — the "smart split"), OR,
   in "Group by domain" mode, Import ▸ Domain. `System.txt`/`Credentials.txt`/
   `ClientAt.txt`/`EmployeeAt.txt` from the original file-explorer spec name
   the raw per-victim file taxonomy of a stealer-log ZIP dump — data this
   importer's input format (the already-restructured "Stealerlogs" victim/
   credential/domain export, not a raw log archive) does not carry per
   credential. Never fabricated: only the two file kinds the data model
   actually distinguishes are shown. */
export async function renderStealer(host, id) {
  host.innerHTML = '<div class="text-muted" style="padding:20px">Loading stealer-log rows…</div>';
  let rows;
  try {
    const r = await API.stealerRows(id);
    rows = r.rows || [];
  } catch (e) {
    host.innerHTML = `<div class="empty-state"><h3>Could not load stealer rows</h3><p>${esc(e.message)}</p></div>`;
    return;
  }
  if (!rows.length) {
    host.innerHTML = '<div class="empty-state"><h3>No stealer-log credential rows</h3>' +
      '<p>This scan has no imported stealer-log data (or it predates the Stealer Logs Viewer).</p></div>';
    return;
  }

  ensureStyles();

  // ── Derived, static-for-this-render indexes ──────────────────────────────
  const machineIds = uniqueSorted(rows.map(r => r.log_id || UNKNOWN_MACHINE));
  const domainIds = uniqueSorted(rows.filter(r => r.domain).map(r => r.domain));
  const hasNoDomainRows = rows.some(r => !r.domain);
  // Cross-machine password reuse — a real correlation signal (the SAME
  // password used on two different logins/machines is far more interesting
  // than a duplicate within one machine) — so this counts across the WHOLE
  // dataset, not just whatever subset is currently in view.
  const passwordCounts = new Map();
  rows.forEach(r => {
    if (!r.password) return;
    passwordCounts.set(r.password, (passwordCounts.get(r.password) || 0) + 1);
  });

  // ── Mutable view state ────────────────────────────────────────────────────
  const state = {
    groupBy: 'machine',       // 'machine' | 'domain'
    selection: null,          // {type:'machine'|'file'|'domain', machine?, kind?, domain?}
    query: '',
    dupOnly: false,
    rawView: false,
    revealed: false,
    sortCol: null,            // 'domain'|'login'|'password'|'kind'|'pwned_at'
    sortDir: 1,
    focusedIdx: -1,
  };

  host.innerHTML = shellHtml(machineIds.length, domainIds.length);

  const treeHost = $('#st-tree', host);
  const tableHost = $('#st-table-host', host);
  const statsHost = $('#st-stats', host);

  function selectedRows() {
    let rs = rows;
    const sel = state.selection;
    if (sel) {
      if (sel.type === 'machine') {
        rs = rs.filter(r => (r.log_id || UNKNOWN_MACHINE) === sel.machine);
      } else if (sel.type === 'file') {
        rs = rs.filter(r => (r.log_id || UNKNOWN_MACHINE) === sel.machine && r.kind === sel.kind);
      } else if (sel.type === 'domain') {
        rs = sel.domain === NO_DOMAIN_KEY
          ? rs.filter(r => !r.domain)
          : rs.filter(r => r.domain === sel.domain);
      }
    }
    const q = state.query.trim().toLowerCase();
    if (q) {
      rs = rs.filter(r =>
        (r.login || '').toLowerCase().includes(q) ||
        (r.password || '').toLowerCase().includes(q) ||
        (r.domain || '').toLowerCase().includes(q) ||
        (r.log_id || '').toLowerCase().includes(q));
    }
    if (state.dupOnly) {
      rs = rs.filter(r => r.password && passwordCounts.get(r.password) > 1);
    }
    if (state.sortCol) {
      const col = state.sortCol, dir = state.sortDir;
      rs = rs.slice().sort((a, b) => {
        const av = (a[col] || '').toString().toLowerCase();
        const bv = (b[col] || '').toString().toLowerCase();
        if (av === bv) return 0;
        if (av === '') return 1;   // blanks always sort last, regardless of direction
        if (bv === '') return -1;
        return av < bv ? -dir : dir;
      });
    }
    return rs;
  }

  function renderTree() {
    treeHost.innerHTML = state.groupBy === 'machine'
      ? machineTreeHtml(rows, machineIds, state.selection)
      : domainTreeHtml(rows, domainIds, hasNoDomainRows, state.selection);
    wireTreeEvents();
  }

  function wireTreeEvents() {
    // #st-tree is fully replaced on every renderTree() call, so its
    // descendants' listeners never accumulate — safe to (re)wire each time.
    $$('.st-node', treeHost).forEach(el => el.addEventListener('click', (e) => {
      e.preventDefault();
      const type = el.dataset.type;
      if (type === 'machine') state.selection = { type: 'machine', machine: el.dataset.machine };
      else if (type === 'file') state.selection = { type: 'file', machine: el.dataset.machine, kind: el.dataset.kind };
      else if (type === 'domain') state.selection = { type: 'domain', domain: el.dataset.domain };
      state.focusedIdx = -1;
      renderTree();
      refresh();
    }));
  }

  function refresh() {
    const rs = selectedRows();
    const domains = new Set(rs.map(r => r.domain).filter(Boolean));
    const passwords = new Set(rs.map(r => r.password).filter(Boolean));
    const dupCount = rs.filter(r => r.password && passwordCounts.get(r.password) > 1).length;
    statsHost.innerHTML =
      `${rs.length} of ${rows.length} entries &middot; ${domains.size} unique domain(s) &middot; ` +
      `${passwords.size} unique password(s) &middot; ` +
      // Row count, not distinct-password count — e.g. 2 rows both using the
      // SAME reused password reads "2 row(s)", not "1 password" (that number
      // is already given by "unique password(s)" above).
      `<span class="${dupCount ? 'text-warning' : 'text-muted'}">${dupCount} row${dupCount === 1 ? '' : 's'} with a reused password</span>`;

    // Render at most STEALER_ROW_CAP rows (the highest-priority slice after any
    // sort/filter). The stats line above and every copy/download/export button
    // still operate on the full matching set `rs`.
    const shown = rs.length > STEALER_ROW_CAP ? rs.slice(0, STEALER_ROW_CAP) : rs;
    tableHost.innerHTML = state.rawView
      ? renderRawHtml(shown, rs.length)
      : renderTableHtml(shown, state, passwordCounts, rs.length);
    wireTableEvents(shown);
  }

  function wireTableEvents(visibleRows) {
    $$('button[data-reveal-row]', tableHost).forEach(b => b.addEventListener('click', () => {
      const cell = b.closest('tr').querySelector('.st-pass-text');
      const shown = cell.dataset.shown === '1';
      cell.textContent = shown ? maskPassword(cell.dataset.value) : cell.dataset.value;
      cell.dataset.shown = shown ? '0' : '1';
    }));
    $$('[data-copy]', tableHost).forEach(el => el.addEventListener('click', () => copyText(el.getAttribute('data-copy'))));
    $$('th[data-sort]', tableHost).forEach(th => th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (state.sortCol === col) state.sortDir = -state.sortDir;
      else { state.sortCol = col; state.sortDir = 1; }
      refresh();
    }));
    // Keyboard navigation: ↑/↓ moves the focused row, Enter reveals+copies its
    // password. Rows are focusable (tabindex) so this also works via Tab.
    const trs = $$('#stealer-table tbody tr', tableHost);
    trs.forEach((tr, i) => {
      tr.tabIndex = 0;
      tr.addEventListener('focus', () => { state.focusedIdx = i; tr.classList.add('st-row-focused'); });
      tr.addEventListener('blur', () => tr.classList.remove('st-row-focused'));
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          (trs[i + 1] || trs[0])?.focus();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          (trs[i - 1] || trs[trs.length - 1])?.focus();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          const r = visibleRows[i];
          if (r && r.password) copyText(r.password);
        }
      });
    });
  }

  // ── Toolbar wiring ────────────────────────────────────────────────────────
  // #st-all lives in the static shell (a sibling of #st-tree, never replaced
  // by renderTree()), so it is wired exactly once here — not inside
  // wireTreeEvents(), which is scoped to #st-tree and would never find it.
  $('#st-all', host).addEventListener('click', (e) => {
    e.preventDefault();
    state.selection = null;
    state.focusedIdx = -1;
    renderTree();
    refresh();
  });
  // Debounced: a re-render + re-wire per keystroke was the other half of the
  // freeze on a large dump.
  const debouncedRefresh = debounce(refresh, 180);
  $('#st-q', host).addEventListener('input', (e) => { state.query = e.target.value; debouncedRefresh(); });
  $('#st-dup', host).addEventListener('change', (e) => { state.dupOnly = e.target.checked; refresh(); });
  $('#st-raw', host).addEventListener('change', (e) => { state.rawView = e.target.checked; refresh(); });
  $('#st-group', host).addEventListener('change', (e) => {
    state.groupBy = e.target.value;
    state.selection = null;
    renderTree();
    refresh();
  });
  $('#st-reveal', host).addEventListener('click', () => {
    state.revealed = !state.revealed;
    $('#st-reveal', host).textContent = state.revealed ? 'Hide all' : 'Reveal all';
    refresh();
  });
  $('#st-expand', host).addEventListener('click', () => $$('#st-tree details', host).forEach(d => d.open = true));
  $('#st-collapse', host).addEventListener('click', () => $$('#st-tree details', host).forEach(d => d.open = false));
  $('#st-copy-logins', host).addEventListener('click', () => copyText(uniqueSorted(selectedRows().map(r => r.login).filter(Boolean)).join('\n')));
  $('#st-copy-passwords', host).addEventListener('click', () => copyText(uniqueSorted(selectedRows().map(r => r.password).filter(Boolean)).join('\n')));
  $('#st-copy-pairs', host).addEventListener('click', () => copyText(exportText(selectedRows())));
  $('#st-download', host).addEventListener('click', () => downloadText(exportText(selectedRows()), `stealer-rows-${id}.txt`));

  renderTree();
  refresh();
}

const UNKNOWN_MACHINE = '(unknown machine)';
const NO_DOMAIN_KEY = '__no-domain';

function uniqueSorted(values) {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

function shellHtml(machineCount, domainCount) {
  return `
    <div class="row">
      <div class="col-sm-3 col-md-2">
        <div class="panel panel-default" style="margin-bottom:8px">
          <div class="panel-heading" style="padding:8px 12px;font-size:12px;font-weight:600">
            <select id="st-group" class="form-control input-sm" style="display:inline-block;width:auto;padding:2px 4px;height:auto">
              <option value="machine">By machine (${machineCount})</option>
              <option value="domain">By domain (${domainCount})</option>
            </select>
            <a href="#" id="st-all" class="pull-right" style="font-size:11px;font-weight:400;line-height:24px">All</a>
          </div>
          <div style="padding:4px 8px;border-bottom:1px solid #eee">
            <a href="#" id="st-expand" style="font-size:11px">Expand all</a>
            &nbsp;&middot;&nbsp;
            <a href="#" id="st-collapse" style="font-size:11px">Collapse all</a>
          </div>
          <div id="st-tree" style="max-height:calc(100vh - 260px);overflow-y:auto;font-size:12px"></div>
        </div>
      </div>
      <div class="col-sm-9 col-md-10">
        <div class="row" style="margin-bottom:6px">
          <div class="col-sm-5">
            <input type="search" id="st-q" class="form-control input-sm" placeholder="Search login, password, domain, machine…" autocomplete="off">
          </div>
          <div class="col-sm-7 text-right" style="padding-top:6px">
            <label class="checkbox-inline" style="font-size:11px;margin-right:8px">
              <input type="checkbox" id="st-dup"> Reused passwords only
            </label>
            <label class="checkbox-inline" style="font-size:11px;margin-right:8px">
              <input type="checkbox" id="st-raw"> Raw view
            </label>
            <button class="btn btn-default btn-xs" id="st-reveal">Reveal all</button>
          </div>
        </div>
        <div class="row" style="margin-bottom:8px">
          <div class="col-sm-12 text-right">
            <div class="btn-group">
              <button class="btn btn-default btn-xs" id="st-copy-logins" title="Copy every distinct visible login, one per line (deduplicated)">Copy logins</button>
              <button class="btn btn-default btn-xs" id="st-copy-passwords" title="Copy every distinct visible password, one per line (deduplicated)">Copy passwords</button>
              <button class="btn btn-default btn-xs" id="st-copy-pairs" title="Copy url:login:pass for every visible row, one per line (not deduplicated)">Copy url:login:pass</button>
              <button class="btn btn-default btn-xs" id="st-download">Download .txt</button>
            </div>
          </div>
        </div>
        <div id="st-stats" class="text-muted" style="margin-bottom:8px;font-size:11px"></div>
        <div id="st-table-host"></div>
      </div>
    </div>
  `;
}

/* Machine ▸ {Passwords.txt, Combos.txt} tree, as nested <details> — native
   expand/collapse, keyboard-accessible with no extra JS state to manage. */
function machineTreeHtml(rows, machineIds, selection) {
  const byMachine = {};
  rows.forEach(r => {
    const m = r.log_id || UNKNOWN_MACHINE;
    (byMachine[m] = byMachine[m] || { password: 0, combo: 0 }).password += r.kind === 'password' ? 1 : 0;
    byMachine[m].combo += r.kind === 'combo' ? 1 : 0;
  });
  const sorted = machineIds.slice().sort((a, b) =>
    (byMachine[b].password + byMachine[b].combo) - (byMachine[a].password + byMachine[a].combo));
  return sorted.map(mid => {
    const counts = byMachine[mid];
    const total = counts.password + counts.combo;
    const isSelMachine = selection?.type === 'machine' && selection.machine === mid;
    const label = mid === UNKNOWN_MACHINE ? mid : (mid.length > 22 ? mid.slice(0, 22) + '…' : mid);
    const fileRow = (kind, name, count) => {
      if (!count) return '';
      const active = selection?.type === 'file' && selection.machine === mid && selection.kind === kind;
      return `<div class="st-node${active ? ' st-node-active' : ''}" data-type="file" data-machine="${attr(mid)}" data-kind="${kind}"
                style="padding:3px 8px 3px 28px;cursor:pointer">
                <i class="glyphicon glyphicon-file" style="font-size:10px;margin-right:4px;opacity:.6"></i>${name}
                <span class="badge" style="float:right">${count}</span>
              </div>`;
    };
    return `<details ${machineIds.length <= 12 ? 'open' : ''}>
      <summary class="st-node${isSelMachine ? ' st-node-active' : ''}" data-type="machine" data-machine="${attr(mid)}"
               style="padding:4px 8px;cursor:pointer;font-family:monospace;font-size:11px" title="${attr(mid)}">
        ${esc(label)} <span class="badge">${total}</span>
      </summary>
      ${fileRow('password', 'Passwords.txt', counts.password)}
      ${fileRow('combo', 'Combos.txt', counts.combo)}
    </details>`;
  }).join('');
}

function domainTreeHtml(rows, domainIds, hasNoDomainRows, selection) {
  const byDomain = {};
  rows.forEach(r => {
    if (!r.domain) return;
    byDomain[r.domain] = (byDomain[r.domain] || 0) + 1;
  });
  const sorted = domainIds.slice().sort((a, b) => byDomain[b] - byDomain[a]);
  const nodes = sorted.map(d => {
    const active = selection?.type === 'domain' && selection.domain === d;
    return `<div class="st-node${active ? ' st-node-active' : ''}" data-type="domain" data-domain="${attr(d)}"
              style="padding:4px 8px;cursor:pointer;word-break:break-all">
              ${esc(d)} <span class="badge">${byDomain[d]}</span>
            </div>`;
  });
  if (hasNoDomainRows) {
    const noDomainCount = rows.filter(r => !r.domain).length;
    const active = selection?.type === 'domain' && selection.domain === NO_DOMAIN_KEY;
    nodes.push(`<div class="st-node${active ? ' st-node-active' : ''}" data-type="domain" data-domain="${NO_DOMAIN_KEY}"
                  style="padding:4px 8px;cursor:pointer" class="text-muted">
                  <em>(no domain — combo rows)</em> <span class="badge">${noDomainCount}</span>
                </div>`);
  }
  return nodes.join('');
}

function sortArrow(state, col) {
  if (state.sortCol !== col) return '';
  return state.sortDir === 1 ? ' &#9650;' : ' &#9660;';
}

function renderTableHtml(rows, state, passwordCounts, total) {
  if (!rows.length) {
    return '<div class="empty-state"><h3>No rows match</h3><p>Adjust the search or filters.</p></div>';
  }
  const capNote = (total != null && total > rows.length)
    ? `<div class="text-muted" style="font-size:11px;margin-bottom:6px">Showing the first ${rows.length} of ${total} matching rows — refine the search, or use <b>Copy</b>/<b>Download .txt</b> for the complete set.</div>`
    : '';
  const q = state.query.trim();
  const body = rows.map(r => {
    const pw = r.password || '';
    const dup = pw && passwordCounts.get(pw) > 1;
    return `<tr${dup ? ' class="st-row-dup"' : ''}>
      <td>${r.domain ? `<span class="tag" style="cursor:pointer" title="Click to copy" data-copy="${attr(r.domain)}">${highlight(r.domain, q)}</span>` : '<span class="text-muted">—</span>'}</td>
      <td style="word-break:break-word"><code>${highlight(r.login || '', q)}</code></td>
      <td>
        ${pw ? `<code class="st-pass-text" data-value="${attr(pw)}" data-shown="${state.revealed ? '1' : '0'}">${state.revealed ? highlight(pw, q) : esc(maskPassword(pw))}</code>
        ${dup ? '<span class="label label-warning" title="This password is reused elsewhere in this scan" style="margin-left:4px">reused</span>' : ''}
        <button class="btn btn-default btn-xs" data-reveal-row title="Reveal/hide"><i class="glyphicon glyphicon-eye-open"></i></button>
        <button class="btn btn-default btn-xs" data-copy="${attr(pw)}" title="Copy password"><i class="glyphicon glyphicon-copy"></i></button>` : '<span class="text-muted">—</span>'}
      </td>
      <td><span class="tag">${r.kind === 'password' ? 'site' : 'combo'}</span></td>
      <td class="text-muted" style="font-size:11px">${esc(r.pwned_at || '')}</td>
    </tr>`;
  }).join('');
  const th = (col, label) => `<th data-sort="${col}" style="cursor:pointer;user-select:none">${label}${sortArrow(state, col)}</th>`;
  return `${capNote}<div class="table-responsive"><table class="table table-striped table-condensed" id="stealer-table">
    <thead><tr>${th('domain', 'Domain')}${th('login', 'Login')}${th('password', 'Password')}${th('kind', 'Type')}${th('pwned_at', 'Captured')}</tr></thead>
    <tbody>${body}</tbody></table></div>`;
}

function renderRawHtml(rows, total) {
  if (!rows.length) {
    return '<div class="empty-state"><h3>No rows match</h3><p>Adjust the search or filters.</p></div>';
  }
  const capNote = (total != null && total > rows.length)
    ? `<div class="text-muted" style="font-size:11px;margin-bottom:6px">Showing the first ${rows.length} of ${total} matching rows — use <b>Download .txt</b> for the complete set.</div>`
    : '';
  return `${capNote}<pre style="white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:calc(100vh - 320px);overflow-y:auto">${esc(exportText(rows))}</pre>`;
}

function highlight(text, q) {
  const escaped = esc(text);
  if (!q) return escaped;
  // Match/slice against the ESCAPED needle, not the raw one — a query
  // containing `&`/`<`/`>`/`"`/`'` escapes to a longer string, so slicing
  // with the raw q.length would cut the <mark> span mid-entity.
  const escapedQ = esc(q);
  const idx = escaped.toLowerCase().indexOf(escapedQ.toLowerCase());
  if (idx === -1) return escaped;
  return escaped.slice(0, idx) + '<mark>' + escaped.slice(idx, idx + escapedQ.length) + '</mark>' + escaped.slice(idx + escapedQ.length);
}

/* url:login:pass when a domain is known, else login:pass — one row per line,
   the "one-click export" the operator can paste elsewhere. Also backs the
   raw-view display, so what you see there is exactly what downloads/copies. */
function exportText(rows) {
  return rows.map(r => (r.domain ? `${r.domain}:` : '') + `${r.login || ''}:${r.password || ''}`).join('\n');
}

function maskPassword(pw) {
  return pw ? '•'.repeat(Math.min(pw.length, 10)) : '';
}

async function copyText(text) {
  if (!text) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    toast('Copied to clipboard');
  } catch (e) {
    toast('Copy failed: ' + e.message, 'err');
  }
}

// Local stealer-row export goes through the shared blob-save path so this
// (in-memory, client-side) ".txt" download and every server-fetched download
// use one identical, cross-browser-reliable save mechanism.
function downloadText(text, filename) {
  triggerBlobDownload(new Blob([text], { type: 'text/plain' }), filename);
}

let stylesInjected = false;
function ensureStyles() {
  if (stylesInjected) return;
  stylesInjected = true;
  const style = document.createElement('style');
  // Reuses this app's own theme variables (see app.css :root / body.light-theme)
  // instead of hardcoded colors — .st-node-active mirrors the Browse tab's own
  // `#browse-rollup tr.active-kind` selected-row treatment for consistency.
  style.textContent = `
    .st-node:hover { background: var(--bg-hover); }
    .st-node-active { background: var(--accent) !important; color: var(--accent-text) !important; font-weight: 600; }
    .st-row-focused { outline: 2px solid var(--accent); outline-offset: -2px; }
    .st-row-dup td { background: var(--warning-dim); }
    /* --warning doesn't flip between themes (see app.css :root), so a fixed
       dark text color keeps <mark> readable in both instead of inheriting
       --text (which flips light in dark mode — unreadable on amber). */
    #st-tree mark, #stealer-table mark { background: var(--warning); color: #1b1200; padding: 0 1px; border-radius: 2px; }
  `;
  document.head.appendChild(style);
}
