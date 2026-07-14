import { API } from '/static/js/api.js';
import { $, attr, esc, toast } from '/static/js/helpers.js';

/* ── Stealer Logs Viewer ──────────────────────────────────────────────────
   Paired login+password+domain+capture-date credential rows from a stealer-
   log import — grouped by source machine (log_id), searchable, with
   reveal/copy on passwords. Powered by /scans/{id}/stealer-rows, which is
   independent of (and richer-paired than) the generic entity graph the
   Browse tab shows: there, a credential's login and password become
   separate, unlinked Email/Username/Credential entities. Deliberately
   scoped down from the full spec for this first increment — duplicate-
   password detection, group-by-domain, a raw view, and the full export set
   (copy-all-logins / copy-all-passwords) are clearly-labeled remainder, not
   silently dropped. */
export async function renderStealer(host, id){
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

  const machines = {};
  rows.forEach(r => {
    const key = r.log_id || '(unknown machine)';
    (machines[key] = machines[key] || []).push(r);
  });
  const machineIds = Object.keys(machines).sort((a, b) => machines[b].length - machines[a].length);

  const sidebarRows = machineIds.map(mid => {
    const label = mid.length > 18 ? mid.slice(0, 18) + '…' : mid;
    return `<tr class="rollup-row" data-machine="${attr(mid)}" style="cursor:pointer">
      <td style="font-family:monospace;font-size:11px" title="${attr(mid)}">${esc(label)}</td>
      <td class="text-right"><b>${machines[mid].length}</b></td>
    </tr>`;
  }).join('');

  host.innerHTML = `
    <div class="row">
      <div class="col-sm-3 col-md-2" id="st-sidebar">
        <div class="panel panel-default" style="margin-bottom:0">
          <div class="panel-heading" style="padding:8px 12px;font-size:12px;font-weight:600">
            Machines &nbsp;<span class="badge">${machineIds.length}</span>
            <a href="#" id="st-all" class="pull-right" style="font-size:11px;font-weight:400">All</a>
          </div>
          <div style="max-height:calc(100vh - 220px);overflow-y:auto">
            <table class="table table-condensed table-hover" style="margin:0;font-size:12px">
              <thead><tr><th>Log ID</th><th class="text-right">Rows</th></tr></thead>
              <tbody>${sidebarRows}</tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="col-sm-9 col-md-10">
        <div class="row" style="margin-bottom:10px">
          <div class="col-sm-5">
            <input type="search" id="st-q" class="form-control input-sm" placeholder="Filter login, password, domain…" autocomplete="off">
          </div>
          <div class="col-sm-3">
            <select id="st-kind" class="form-control input-sm">
              <option value="">All rows</option>
              <option value="password">Passwords (site)</option>
              <option value="combo">Combos (no site)</option>
            </select>
          </div>
          <div class="col-sm-4 text-right" style="padding-top:2px">
            <button class="btn btn-default btn-xs" id="st-reveal">Reveal all</button>
            <button class="btn btn-default btn-xs" id="st-export">Copy visible</button>
            <button class="btn btn-default btn-xs" id="st-download">Download .txt</button>
          </div>
        </div>
        <input type="hidden" id="st-machine" value="">
        <div id="st-stats" class="text-muted" style="margin-bottom:8px;font-size:11px"></div>
        <div id="st-table-host"></div>
      </div>
    </div>
  `;

  let revealed = false;

  function currentRows(){
    const q = $('#st-q').value.trim().toLowerCase();
    const kind = $('#st-kind').value;
    const machine = $('#st-machine').value;
    let rs = rows;
    if (machine) rs = rs.filter(r => (r.log_id || '(unknown machine)') === machine);
    if (kind) rs = rs.filter(r => r.kind === kind);
    if (q) rs = rs.filter(r =>
      (r.login || '').toLowerCase().includes(q) ||
      (r.password || '').toLowerCase().includes(q) ||
      (r.domain || '').toLowerCase().includes(q));
    return rs;
  }

  function refresh(){
    const rs = currentRows();
    const domains = new Set(rs.map(r => r.domain).filter(Boolean));
    const passwords = new Set(rs.map(r => r.password).filter(Boolean));
    $('#st-stats').textContent =
      `${rs.length} of ${rows.length} entries · ${domains.size} unique domain(s) · ${passwords.size} unique password(s)`;
    $('#st-table-host').innerHTML = renderStealerTable(rs, revealed);
    host.querySelectorAll('button[data-reveal-row]').forEach(b => b.addEventListener('click', () => {
      const cell = b.closest('tr').querySelector('.st-pass-text');
      const shown = cell.dataset.shown === '1';
      cell.textContent = shown ? maskPassword(cell.dataset.value) : cell.dataset.value;
      cell.dataset.shown = shown ? '0' : '1';
    }));
    host.querySelectorAll('[data-copy]').forEach(el => el.addEventListener('click', () => {
      copyText(el.getAttribute('data-copy'));
    }));
  }

  $('#st-q').addEventListener('input', refresh);
  $('#st-kind').addEventListener('change', refresh);
  host.querySelectorAll('.rollup-row').forEach(tr => tr.addEventListener('click', () => {
    const m = tr.getAttribute('data-machine');
    const inp = $('#st-machine');
    inp.value = (inp.value === m) ? '' : m;
    host.querySelectorAll('.rollup-row').forEach(r =>
      r.classList.toggle('active-kind', r.getAttribute('data-machine') === inp.value && inp.value !== ''));
    refresh();
  }));
  $('#st-all').addEventListener('click', e => {
    e.preventDefault();
    $('#st-machine').value = '';
    host.querySelectorAll('.rollup-row').forEach(r => r.classList.remove('active-kind'));
    refresh();
  });
  $('#st-reveal').addEventListener('click', () => {
    revealed = !revealed;
    $('#st-reveal').textContent = revealed ? 'Hide all' : 'Reveal all';
    refresh();
  });
  $('#st-export').addEventListener('click', () => copyText(exportText(currentRows())));
  $('#st-download').addEventListener('click', () => downloadText(exportText(currentRows()), `stealer-rows-${id}.txt`));

  refresh();
}

/* url:login:pass when a domain is known, else login:pass — one row per line,
   the "one-click export" the operator can paste elsewhere. */
function exportText(rows){
  return rows.map(r => (r.domain ? `${r.domain}:` : '') + `${r.login || ''}:${r.password || ''}`).join('\n');
}

function maskPassword(pw){
  return pw ? '•'.repeat(Math.min(pw.length, 10)) : '';
}

function renderStealerTable(rows, revealed){
  if (!rows.length) {
    return '<div class="empty-state"><h3>No rows match</h3><p>Adjust the filter.</p></div>';
  }
  const body = rows.map(r => {
    const pw = r.password || '';
    return `<tr>
      <td>${r.domain ? `<span class="tag" style="cursor:pointer" title="Click to copy" data-copy="${attr(r.domain)}">${esc(r.domain)}</span>` : '<span class="text-muted">—</span>'}</td>
      <td style="word-break:break-word"><code>${esc(r.login || '')}</code></td>
      <td>
        ${pw ? `<code class="st-pass-text" data-value="${attr(pw)}" data-shown="${revealed ? '1' : '0'}">${esc(revealed ? pw : maskPassword(pw))}</code>
        <button class="btn btn-default btn-xs" data-reveal-row title="Reveal/hide"><i class="glyphicon glyphicon-eye-open"></i></button>
        <button class="btn btn-default btn-xs" data-copy="${attr(pw)}" title="Copy password"><i class="glyphicon glyphicon-copy"></i></button>` : '<span class="text-muted">—</span>'}
      </td>
      <td><span class="tag">${r.kind === 'password' ? 'site' : 'combo'}</span></td>
      <td class="text-muted" style="font-size:11px">${esc(r.pwned_at || '')}</td>
    </tr>`;
  }).join('');
  return `<div class="table-responsive"><table class="table table-striped table-condensed" id="stealer-table">
    <thead><tr><th>Domain</th><th>Login</th><th>Password</th><th>Type</th><th>Captured</th></tr></thead>
    <tbody>${body}</tbody></table></div>`;
}

async function copyText(text){
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

function downloadText(text, filename){
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
