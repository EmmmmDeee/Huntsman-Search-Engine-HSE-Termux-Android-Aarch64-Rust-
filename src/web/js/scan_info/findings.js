import { $, attr, classify, effC, esc, extLink, kindToStr } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';

/* ── Key Findings — the first thing on the Report, above every analytical
   section. A people-search's whole point is the harvested selectors (emails,
   names, phones, usernames, addresses); those were previously reachable only by
   drilling into the Browse tab or scanning fourteen synthesis panels. This
   surfaces them immediately: the highest-value identity kinds, each row's
   strongest values first, tier-coloured and (for URLs) clickable, so a glance
   answers "what did we find about this person."

   Reads the already-loaded `S.entities` synchronously — no extra API round-trip,
   which matters on a Termux mobile link. ── */

// People-centric kinds in display priority order, with a friendly label + glyph.
// Only these are promoted to the summary; infrastructure/derived kinds stay in
// Browse so the summary is never diluted by noise.
const PRIORITY_KINDS = [
  ['person',      'Names',      'user'],
  ['email',       'Emails',     'envelope'],
  ['phone',       'Phones',     'phone-alt'],
  ['username',    'Usernames',  'tag'],
  ['address',     'Addresses',  'map-marker'],
  ['url',         'Profiles & URLs', 'link'],
  ['password',    'Credentials', 'lock'],
  ['ip_address',  'IP addresses', 'globe'],
  ['coordinates', 'Coordinates', 'screenshot'],
];

// Max values shown per kind before a "+N more" link into Browse — keeps the
// summary glanceable even when a kind has hundreds of values.
const PER_KIND_CAP = 12;

const TIER_CLASS = { VERIFIED: 'label-success', PROBABLE: 'label-primary', CANDIDATE: 'label-default' };

export function renderFindings(host, id){
  const ents = S.entities || [];
  if (!ents.length){ host.innerHTML = ''; return; }

  // Bucket by normalised kind so `Other(s)` object-kinds never crash the group.
  const byKind = new Map();
  for (const e of ents){
    const k = kindToStr(e.kind);
    let arr = byKind.get(k);
    if (!arr){ arr = []; byKind.set(k, arr); }
    arr.push(e);
  }

  let sections = '';
  let shown = 0;
  for (const [kind, label, glyph] of PRIORITY_KINDS){
    const rows = byKind.get(kind);
    if (!rows || !rows.length) continue;
    shown++;
    // Strongest first: effective confidence desc, then value for stable order.
    rows.sort((a, b) => (effC(b) - effC(a)) || String(a.value).localeCompare(String(b.value)));
    const head = rows.slice(0, PER_KIND_CAP);
    const overflow = rows.length - head.length;
    const chips = head.map(e => {
      const tier = classify(effC(e));
      const cls = TIER_CLASS[tier] || 'label-default';
      const val = kind === 'url' ? extLink(e.value, 48) : esc(e.value);
      return `<span class="label ${cls} kf-chip" title="${attr(tier)} · effective confidence ${(effC(e)).toFixed(2)}">${val}</span>`;
    }).join(' ');
    const moreLink = overflow > 0
      ? ` <a href="#" class="kf-more" data-kind="${attr(kind)}" style="font-size:11px">+${overflow} more →</a>`
      : '';
    sections += `<div class="kf-group" style="margin-bottom:10px">
      <div style="font-size:12px;font-weight:600;color:#666;margin-bottom:4px">
        <i class="glyphicon glyphicon-${glyph}"></i>&nbsp;${esc(label)}
        <span class="text-muted" style="font-weight:400">(${rows.length})</span>
      </div>
      <div class="kf-chips">${chips}${moreLink}</div>
    </div>`;
  }

  if (!shown){ host.innerHTML = ''; return; }

  host.innerHTML = `
    <div class="panel panel-default" style="border-left:4px solid #5cb85c">
      <div class="panel-heading" style="background:rgba(92,184,92,0.08);font-weight:600">
        <i class="glyphicon glyphicon-star"></i>&nbsp;Key findings
        <span class="text-muted" style="font-weight:400;font-size:12px;margin-left:6px">
          highest-value identity data harvested for this target — strongest first
        </span>
      </div>
      <div class="panel-body" style="padding:12px 14px">${sections}</div>
    </div>`;

  // "+N more" jumps to the Browse tab pre-filtered to that kind, where the full
  // paginated, searchable table lives — no duplicate rendering here.
  host.querySelectorAll('.kf-more').forEach(a => a.addEventListener('click', e => {
    e.preventDefault();
    nav(`#/scaninfo?id=${id}&tab=browse&k=${encodeURIComponent(a.dataset.kind)}`);
  }));
}
