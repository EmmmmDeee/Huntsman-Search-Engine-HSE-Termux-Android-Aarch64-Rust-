/* Vanilla-JS replacements for the vendored Bootstrap-JS/jQuery/tablesorter/
 * alertify behaviours the SPA used to depend on. None of the ~40 view files
 * needed to change: the navbar/modal markup keeps its original `data-toggle`/
 * `data-target`/`data-dismiss` attributes, and `window.jQuery`/`window.alertify`
 * are shimmed with just enough surface for the existing call sites
 * (`jQuery('#id').tablesorter(opts)`, `alertify.success/error/warning/notify/
 * confirm/prompt`) to keep working verbatim. Import this once from main.js.
 */
import { esc } from '/static/js/helpers.js';

/* ─── Navbar collapse (mobile hamburger) ─── */
export function initNavbarToggle(){
  document.addEventListener('click', e=>{
    const btn = e.target.closest('.navbar-toggle');
    if (!btn) return;
    const target = document.querySelector(btn.dataset.target || btn.getAttribute('href') || '');
    if (!target) return;
    const open = target.classList.toggle('in');
    btn.setAttribute('aria-expanded', String(open));
  });
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
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b)=>{
    const av = cellSortValue(a.children[col] || {});
    const bv = cellSortValue(b.children[col] || {});
    if (av < bv) return dir === 'asc' ? -1 : 1;
    if (av > bv) return dir === 'asc' ? 1 : -1;
    return 0;
  });
  rows.forEach(r=>tbody.appendChild(r));
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
