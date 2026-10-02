/* Vanilla-JS replacements for the vendored Bootstrap-JS/jQuery/tablesorter/
 * alertify behaviours the SPA used to depend on. None of the ~40 view files
 * needed to change: the navbar/modal markup keeps its original `data-toggle`/
 * `data-target`/`data-dismiss` attributes, and `window.jQuery`/`window.alertify`
 * are shimmed with just enough surface for the existing call sites
 * (`jQuery('#id').tablesorter(opts)`, `alertify.success/error/warning/notify/
 * confirm/prompt`) to keep working verbatim. Import this once from main.js.
 */
import { esc } from '/static/js/helpers.js';

/* ─── Navbar: collapse toggle and dropdowns (SpiderFoot's Bootstrap JS) ───
 *
 * Below 1100px the navbar's links sit behind the three-bar toggle, as
 * Bootstrap's collapse does in SpiderFoot 4.0 (whose bar collapses at 768px:
 * HSE's text brand makes the full bar about 1,030px wide; see app.css's
 * Navbar section). Dropdowns — the navbar's
 * "More" menu and any view's `data-toggle="dropdown"` button, such as an
 * Export menu — open on click, and close on a second click, a click anywhere
 * else, picking an item, Escape, or navigating. A menu left open after the
 * route changes would float over a page it no longer belongs to. */
function closeDropdowns(except){
  document.querySelectorAll('.dropdown.open, .btn-group.open, .dropup.open').forEach(el=>{
    if (el === except) return;
    el.classList.remove('open');
    const t = el.querySelector(':scope > .dropdown-toggle, :scope > [data-toggle="dropdown"]');
    if (t) t.setAttribute('aria-expanded', 'false');
  });
}
export function initNavbar(){
  const toggle   = document.getElementById('navbar-toggle');
  const collapse = document.getElementById('main-navbar-collapse');
  const setCollapsed = open => {
    if (!toggle || !collapse) return;
    collapse.classList.toggle('in', open);
    toggle.classList.toggle('collapsed', !open);
    toggle.setAttribute('aria-expanded', String(open));
  };
  if (toggle && collapse){
    toggle.addEventListener('click', e=>{
      e.preventDefault();
      setCollapsed(!collapse.classList.contains('in'));
    });
  }

  document.addEventListener('click', e=>{
    const opener = e.target.closest('[data-toggle="dropdown"], .dropdown-toggle');
    if (opener){
      e.preventDefault();
      const host = opener.closest('.dropdown, .btn-group, .dropup') || opener.parentElement;
      const willOpen = !host.classList.contains('open');
      closeDropdowns(host);
      host.classList.toggle('open', willOpen);
      opener.setAttribute('aria-expanded', String(willOpen));
      return;
    }
    // An item inside a menu has been chosen, or the click landed elsewhere.
    closeDropdowns(null);
    if (e.target.closest('#main-navbar-collapse a[href^="#/"]')) setCollapsed(false);
  });
  document.addEventListener('keydown', e=>{
    if (e.key !== 'Escape') return;
    // Focus goes back to the toggle of the menu being closed, as Bootstrap's
    // dropdown does, so a keyboard user is not dropped at the top of the page.
    const open = document.querySelector('.dropdown.open, .btn-group.open, .dropup.open');
    const back = open && open.querySelector(':scope > .dropdown-toggle, :scope > [data-toggle="dropdown"]');
    closeDropdowns(null);
    setCollapsed(false);
    if (back) back.focus();
  });
  window.addEventListener('hashchange', ()=>{ closeDropdowns(null); setCollapsed(false); });

  syncNavbarHeight();
  const nav = document.getElementById('mainnav');
  if (nav && typeof ResizeObserver === 'function') new ResizeObserver(syncNavbarHeight).observe(nav);
  window.addEventListener('resize', syncNavbarHeight);
}

/* The page's top padding is `--navbar-h` (app.css). It is the bar's measured
 * height, not a constant, so a navbar that grows (a larger default font can
 * wrap it) never covers the page. With the links collapsed, only the header
 * row counts: the open menu overlays the page, as Bootstrap's does, rather
 * than pushing it down. */
function syncNavbarHeight(){
  const nav = document.getElementById('mainnav');
  const toggle = document.getElementById('navbar-toggle');
  if (!nav) return;
  const collapsed = toggle && getComputedStyle(toggle).display !== 'none';
  const header = nav.querySelector('.navbar-header');
  const h = collapsed && header
    // The header row plus the bar's own top padding (the safe-area inset).
    ? header.getBoundingClientRect().bottom - nav.getBoundingClientRect().top
    : nav.getBoundingClientRect().height;
  if (h > 0) document.documentElement.style.setProperty('--navbar-h', `${Math.ceil(h)}px`);
}

/* ─── Footer tip (SpiderFoot's FOOTER.tmpl shows one, picked per page) ───
 * main.js calls this when the page changes, not on every render: a running
 * scan's page re-renders every few seconds, and a tip that changed with it
 * would flicker and, on a phone, change the footer's height. */
const FOOTER_TIPS = [
  ['glyphicon-console',      'Did you know HSE also has a CLI? Run <code>hse --help</code> in Termux.'],
  ['glyphicon-lock',         'Keep API keys in <code>$HOME/.huntsman.env</code> (chmod 0600) — never in chat or screenshots.'],
  ['glyphicon-record',       'Live Scans re-run a target on an interval. Find them under More → Live Scans.'],
  ['glyphicon-map-marker',   'Signal Radar maps nearby Wi-Fi and Bluetooth devices. Find it under More → Signal Radar.'],
  ['glyphicon-transfer',     'Compare two scans of the same subject over time with More → Compare Scans.'],
  ['glyphicon-download-alt', 'Exports are client-safe: breach sources appear as numbered placeholders, never by name.'],
  ['glyphicon-search',       'Search every entity across every scan at once with More → Search All Scans.'],
  ['glyphicon-education',    'The scan\'s Graph, Correlations and Browse views all read the same entities — pivot from any of them.'],
];
export function showFooterTip(){
  const el = document.getElementById('footer-tip');
  if (!el) return;
  const [icon, text] = FOOTER_TIPS[Math.floor(Math.random() * FOOTER_TIPS.length)];
  el.innerHTML = `<i class="glyphicon ${icon}" aria-hidden="true"></i>${text}`;
}

/* ─── Responsive tables ───
 *
 * A seven-column scan table is 744px wide; a phone gives it 343px. It survived
 * only because `.table-responsive` scrolls sideways, which means status, entity
 * count and the row's own action buttons all sat off-screen behind a gesture
 * nothing advertised.
 *
 * Below the layout breakpoint the CSS restacks each row into a labelled card.
 * That needs every cell to know its column name, and the ~40 view files build
 * their markup as template strings with no such attribute. Rather than edit all
 * of them, copy the header text down into `data-label` once per render: the
 * header is already right there in the same table, and doing it here means any
 * table added later reflows without its author having to know this exists.
 *
 * Header-less tables (used for layout rather than data) are skipped, so they
 * keep their current behaviour. */
export function labelTables(root){
  (root || document).querySelectorAll('.table-responsive table').forEach(table => {
    const heads = [...table.querySelectorAll('thead th')].map(th => th.textContent.trim());
    if (!heads.length) return;
    table.querySelectorAll('tbody tr').forEach(tr => {
      [...tr.children].forEach((td, i) => {
        const label = heads[i];
        if (label && !td.dataset.label) td.dataset.label = label;
      });
    });
  });
}

/* Label on every paint, not just the router's.
 *
 * Tables appear well after a route finishes rendering — scan-info swaps panels
 * on tab clicks, several views poll and repaint, the live log appends rows —
 * so hooking the router alone would leave most tables in the app unlabelled and
 * therefore unlabelled-looking once restacked. Observing the mount point covers
 * every one of those paths from a single place, and the pass is idempotent
 * (cells already carrying a label are skipped). */
export function initTableLabels(){
  const view = document.getElementById('view');
  if (!view) return;
  labelTables(view);
  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    // Coalesce a burst of DOM writes into one pass at the end of the frame.
    requestAnimationFrame(() => { queued = false; labelTables(view); });
  }).observe(view, { childList:true, subtree:true });
}

/* ─── Modal (About dialog, and any future data-toggle="modal" trigger) ─── */
export function initModals(){
  document.addEventListener('click', e=>{
    const opener = e.target.closest('[data-toggle="modal"]');
    if (opener){
      e.preventDefault();
      const sel = opener.dataset.target || opener.getAttribute('href');
      const modal = sel && document.querySelector(sel);
      if (modal) openModal(modal);
      return;
    }
    const dismiss = e.target.closest('[data-dismiss="modal"]');
    if (dismiss){
      const modal = dismiss.closest('.modal');
      if (modal) closeModal(modal);
      return;
    }
    if (e.target.classList && e.target.classList.contains('modal') && e.target.classList.contains('in')){
      closeModal(e.target);
    }
  });
  document.addEventListener('keydown', e=>{
    if (e.key !== 'Escape') return;
    const open = document.querySelector('.modal.in');
    if (open) closeModal(open);
  });
}
function openModal(modal){
  modal.classList.add('in');
  document.body.classList.add('modal-open');
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  document.body.appendChild(backdrop);
}
function closeModal(modal){
  modal.classList.remove('in');
  document.body.classList.remove('modal-open');
  document.querySelectorAll('.modal-backdrop').forEach(b=>b.remove());
}

/* ─── Sortable tables (tablesorter replacement) ───
 * `sortList: [[colIndex, dir]]` (dir 0=asc, 1=desc) mirrors the subset of
 * tablesorter's option object the existing call sites actually pass. */
export function sortableTable(table, opts){
  if (!table) return;
  const heads = table.querySelectorAll('thead th');
  heads.forEach((th, i)=>{
    if (th.classList.contains('sorter-false')) return;
    th.addEventListener('click', ()=> applySort(table, i, heads));
  });
  const initial = opts && opts.sortList && opts.sortList[0];
  if (initial){
    const [col, dir] = initial;
    applySort(table, col, heads, dir===1 ? 'desc' : 'asc');
  }
}
function cellSortValue(td){
  const raw = (td.textContent || '').trim();
  const num = Number(raw.replace(/[,%]/g, ''));
  return Number.isFinite(num) && raw !== '' ? num : raw.toLowerCase();
}
function applySort(table, col, heads, forceDir){
  const th = heads[col];
  const dir = forceDir || (th.classList.contains('sort-asc') ? 'desc' : 'asc');
  heads.forEach(h=>h.classList.remove('sort-asc', 'sort-desc'));
  th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
  const tbody = table.querySelector('tbody');
  if (!tbody) return;
  // Group each primary row with an immediately-following hidden detail panel
  // (e.g. scan_info/browse.js's click-to-expand evidence row,
  // `.entity-detail-row`) and sort/re-append the GROUP as one unit. Sorting
  // every `<tr>` independently — the previous behaviour — silently splits a
  // primary row from its detail row (they land in unrelated positions once
  // reordered by a column the detail row has no cell for), and
  // `toggleDetail()` locates the panel via `nextElementSibling`, so a split
  // pair makes the expand/collapse click do nothing. Harmless no-op for
  // tables with no detail rows (every group is just the row itself).
  const allRows = Array.from(tbody.querySelectorAll('tr'));
  const groups = [];
  for (let i = 0; i < allRows.length; i++){
    const row = allRows[i];
    if (row.classList.contains('entity-detail-row')) continue; // consumed below
    const next = allRows[i + 1];
    const detail = next && next.classList.contains('entity-detail-row') ? next : null;
    if (detail) i++;
    groups.push({ primary: row, detail });
  }
  groups.sort((a, b)=>{
    const av = cellSortValue(a.primary.children[col] || {});
    const bv = cellSortValue(b.primary.children[col] || {});
    if (av < bv) return dir === 'asc' ? -1 : 1;
    if (av > bv) return dir === 'asc' ? 1 : -1;
    return 0;
  });
  groups.forEach(g=>{ tbody.appendChild(g.primary); if (g.detail) tbody.appendChild(g.detail); });
}

/* ─── window.jQuery shim ───
 * Just enough surface for `window.jQuery && jQuery.fn.tablesorter &&
 * jQuery('#id').tablesorter(opts)` to keep working unchanged. */
function installJQueryShim(){
  function jQueryShim(sel){
    const el = typeof sel === 'string' ? document.querySelector(sel) : sel;
    return {
      tablesorter(opts){ if (el) sortableTable(el, opts); return this; },
    };
  }
  jQueryShim.fn = { tablesorter: true };
  window.jQuery = jQueryShim;
}

/* ─── window.alertify shim ───
 * Matches the call contract every view file already uses:
 * success(msg) / error(msg) / warning(msg) / notify(msg, kind, wait) /
 * confirm(title, msg, onOk, onCancel) / prompt(title, msg, dflt, onOk, onCancel) /
 * set(...) (no-op — was only ever used to reposition the old notifier). */
function toastEl(){
  let box = document.getElementById('hse-toasts');
  if (!box){
    box = document.createElement('div');
    box.id = 'hse-toasts';
    document.body.appendChild(box);
  }
  return box;
}
function showToast(msg, kind){
  const box = toastEl();
  const el = document.createElement('div');
  el.className = `hse-toast ${kind}`;
  el.innerHTML = esc(String(msg));
  box.appendChild(el);
  setTimeout(()=>el.remove(), 4000);
}
function showDialog({ title, message, withInput, dflt, onOk, onCancel }){
  const backdrop = document.createElement('div');
  backdrop.className = 'hse-dialog-backdrop';
  backdrop.innerHTML = `
    <div class="hse-dialog">
      <div class="hse-dialog-title">${esc(title)}</div>
      <div class="hse-dialog-body">
        <p>${esc(message)}</p>
        ${withInput ? `<input type="text" class="form-control" id="hse-dialog-input" value="${esc(dflt || '')}">` : ''}
      </div>
      <div class="hse-dialog-footer">
        <button type="button" class="btn btn-default" id="hse-dialog-cancel">Cancel</button>
        <button type="button" class="btn btn-primary" id="hse-dialog-ok">OK</button>
      </div>
    </div>`;
  document.body.appendChild(backdrop);
  const input = backdrop.querySelector('#hse-dialog-input');
  if (input) input.focus();
  const cleanup = ()=>backdrop.remove();
  backdrop.querySelector('#hse-dialog-ok').addEventListener('click', ()=>{
    const val = input ? input.value : undefined;
    cleanup();
    if (onOk) onOk({}, val);
  });
  backdrop.querySelector('#hse-dialog-cancel').addEventListener('click', ()=>{
    cleanup();
    if (onCancel) onCancel();
  });
  backdrop.addEventListener('click', e=>{
    if (e.target === backdrop){ cleanup(); if (onCancel) onCancel(); }
  });
}
function installAlertifyShim(){
  window.alertify = {
    success(msg){ showToast(msg, 'success'); },
    error(msg){ showToast(msg, 'error'); },
    warning(msg){ showToast(msg, 'warning'); },
    notify(msg, kind){ showToast(msg, kind === 'error' ? 'error' : kind === 'warning' ? 'warning' : 'success'); },
    confirm(title, message, onOk, onCancel){ showDialog({ title, message, onOk, onCancel }); },
    prompt(title, message, dflt, onOk, onCancel){
      showDialog({ title, message, withInput: true, dflt, onOk, onCancel });
    },
    set(){ /* no-op — was only ever used to position the old notifier */ },
  };
}

export function initCompatShims(){
  installJQueryShim();
  installAlertifyShim();
}
