/* Vanilla-JS replacements for the vendored Bootstrap-JS/jQuery/tablesorter/
 * alertify behaviours the SPA used to depend on. None of the ~40 view files
 * needed to change: the navbar/modal markup keeps its original `data-toggle`/
 * `data-target`/`data-dismiss` attributes, and `window.jQuery`/`window.alertify`
 * are shimmed with just enough surface for the existing call sites
 * (`jQuery('#id').tablesorter(opts)`, `alertify.success/error/warning/notify/
 * confirm/prompt`) to keep working verbatim. Import this once from main.js.
 */
import { esc } from '/static/js/helpers.js';

/* ─── "More" sheet (narrow screens; the panel flows inline from 768px up) ───
 *
 * Replaces the old hamburger, which collapsed the whole nav behind a tap. The
 * primary destinations now live permanently in the bottom tab bar, so this only
 * raises the secondary ones. Closing on outside-tap, Escape and navigation
 * matters more here than it did for a dropdown: the sheet covers the tab bar it
 * sits on, so leaving it open would hide the primary navigation behind it. */
export function initMoreSheet(){
  const btn   = document.getElementById('more-toggle');
  const panel = document.getElementById('morepanel');
  if (!btn || !panel) return;

  const setOpen = open => {
    panel.classList.toggle('open', open);
    // Deliberately not `.active`: that marks the destination you are ON, and
    // the route behind the sheet still owns it. Two accented tabs would say
    // you are in two places at once.
    btn.classList.toggle('sheet-open', open);
    btn.setAttribute('aria-expanded', String(open));
  };

  btn.addEventListener('click', e=>{
    e.preventDefault();
    setOpen(!panel.classList.contains('open'));
  });
  // Picking a destination, tapping elsewhere, or Escape all dismiss it.
  panel.addEventListener('click', e=>{ if (e.target.closest('.navlink')) setOpen(false); });
  document.addEventListener('click', e=>{
    if (!panel.classList.contains('open')) return;
    if (e.target.closest('#morepanel') || e.target.closest('#more-toggle')) return;
    setOpen(false);
  });
  document.addEventListener('keydown', e=>{ if (e.key === 'Escape') setOpen(false); });
  // A hash change can also come from a link inside a view, not just the sheet.
  window.addEventListener('hashchange', ()=>setOpen(false));
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
