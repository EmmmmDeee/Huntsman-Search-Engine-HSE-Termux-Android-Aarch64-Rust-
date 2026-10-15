#!/usr/bin/env node
// The serve web UI in a phone's browser, checked end to end. It starts `huntsman-recon serve` on a
// free loopback port, drives the page at 360x740 with touch in both system themes, and fails when
// a behaviour the page promises does not hold: it loads with no console error or policy
// violation, fits the screen with 44 px targets, passes axe-core's WCAG 2.2 AA rules in every
// view of both themes, runs a scan one hop deep from New Scan to FINISHED and shows exactly what
// the scan API holds in its Summary, Browse, Correlations, Graph, Scan Settings and Log sections,
// marks a false positive, searches, exports, clones, re-runs, compares and deletes a scan, keeps
// its place across a reload, asks only for health when a tab with nothing running comes back,
// says what to do when the server stops, notices when it is back, and finds the saved scans
// still there after the restart.
//
// It never spends a key: the server runs with a scratch HOME and none of the caller's
// HUNTSMAN_*, HSE_* or *_KEY variables, and its scans target a phone number, which is offline.
//
// Usage:  node tools/web-ui-check/check.cjs path/to/huntsman-recon
// Needs:  playwright-core (or playwright) and axe-core next to this file or on NODE_PATH, and a
//         Chromium: CHROME_PATH, else CHROME_BIN, else Playwright's own.
// Prints one JSON object of measurements; exits 1 when any check fails.
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

function need(names) {
  for (const name of names) { try { return require(name); } catch (_) {} }
  process.stderr.write(`web-ui-check: install one of ${names.join(', ')} (npm install --no-save ${names[0]})\n`);
  process.exit(2);
}
const { chromium } = need(['playwright-core', 'playwright']);
const AXE = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const bin = process.argv[2];
if (!bin || !fs.existsSync(bin)) { process.stderr.write('usage: node check.cjs path/to/huntsman-recon\n'); process.exit(64); }
const PHONE = { viewport: { width: 360, height: 740 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true };
const PAGE_BUDGET = 112 * 1024;
const TARGET = '+61412345678';
const failures = [];
const metrics = {};
function check(name, ok, detail) { if (!ok) failures.push(`${name}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`); }

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'hse-web-ui-'));
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(HUNTSMAN_|HSE_)|_KEY$|TOKEN|SECRET/.test(k)));
env.HOME = home;
let server = null;
function serve(bind) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ['serve', '--bind', bind], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const timer = setTimeout(() => reject(new Error('serve did not print serving= within 10 s: ' + out)), 10000);
    child.stdout.on('data', chunk => {
      out += chunk;
      const m = /serving=(http:\/\/\S+?)\/?\s/.exec(out);
      if (m) { clearTimeout(timer); server = child; resolve(m[1]); }
    });
    child.on('exit', code => { clearTimeout(timer); if (server !== child) reject(new Error(`serve exited ${code}: ${out}`)); });
  });
}
function stop() { return new Promise(done => { if (!server) return done(); server.once('exit', () => done()); server.kill('SIGKILL'); server = null; }); }

async function axe(page, where) {
  await page.evaluate(AXE);
  const violations = await page.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] } })).violations
    .map(v => `${v.id} (${v.nodes.length}): ${v.nodes.slice(0, 2).map(n => n.target.join(' ') + (n.any[0] ? ' ' + n.any[0].message : '')).join(' | ')}`));
  check(`axe ${where}`, violations.length === 0, violations);
}
// Every visible control is at least 44 px; a checkbox or radio counts as the label that holds it.
async function fits(page, where) {
  const m = await page.evaluate(() => {
    const box = e => (e.matches('input[type=checkbox],input[type=radio]') && e.closest('label') || e).getBoundingClientRect();
    const controls = [...document.querySelectorAll('button,input,select,textarea,a,summary')].filter(e => e.offsetParent !== null && e.getBoundingClientRect().width > 0);
    return {
      overflowPx: document.documentElement.scrollWidth - window.innerWidth,
      small: controls.filter(e => { const r = box(e); return r.height < 44 || r.width < 44; }).map(e => e.id || e.tagName + ':' + e.textContent.trim().slice(0, 20)),
    };
  });
  check(`${where}: fits 360 px`, m.overflowPx <= 0, `${m.overflowPx} px of horizontal overflow`);
  check(`${where}: tap targets of 44 px`, m.small.length === 0, m.small);
}
async function audit(page, where) { await axe(page, where); await fits(page, where); }
const SEEDS = ['alice@example.com', 'example.com', '@alice', '+61412345678', 'Alice Smith', '203.0.113.7'].join('\n');
const LH = { 'X-Huntsman-Lookup': '1' };

(async () => {
  const base = await serve('127.0.0.1:0');
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || process.env.CHROME_BIN || undefined });
  const api = async (page, p) => (await page.request.get(base + p, { headers: LH })).json();
  // Runs a scan through New Scan, following what it finds `depth` hops, and waits for it to
  // finish; answers its id and how long it took.
  async function newScan(page, name, depth) {
    await page.goto(base + '/#/newscan', { waitUntil: 'networkidle' });
    await page.fill('#starget', TARGET);
    await page.fill('#sname', name);
    await page.fill('#sdepth', String(depth));
    const t = Date.now();
    await page.click('#runscan');
    await page.waitForFunction(() => /^#\/scan\/[^/]+/.test(location.hash) && !document.getElementById('view-scan').hidden, null, { timeout: 10000 });
    const id = decodeURIComponent((await page.evaluate(() => location.hash)).split('/')[2]);
    await page.waitForFunction(() => ['FINISHED', 'ABORTED', 'ERROR-FAILED'].includes(document.getElementById('scstatus').textContent), null, { timeout: 90000 }).catch(() => {});
    return { id, ms: Date.now() - t, status: await page.textContent('#scstatus') };
  }
  async function tabReturns(page, n) {
    const asked = [];
    const seen = r => { const p = new URL(r.url()).pathname; if (p.startsWith('/api/')) asked.push(p); };
    page.on('request', seen);
    for (let i = 0; i < n; i++) {
      await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange')); });
      await page.waitForTimeout(200);
    }
    page.off('request', seen);
    return asked;
  }
  let kept = 0;
  try {
    // Cold load: what arrives, how it fits, and that the browser runs it under its policy.
    {
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      const errors = [], paths = [];
      page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
      page.on('pageerror', e => errors.push(String(e)));
      page.on('request', r => paths.push(new URL(r.url()).pathname));
      await page.addInitScript(() => document.addEventListener('securitypolicyviolation', e => (window.__csp = window.__csp || []).push(e.violatedDirective)));
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      // The page's own health call settles the pill; a browser can go network-idle just before.
      await page.waitForFunction(() => document.getElementById('state').textContent !== 'connecting', null, { timeout: 5000 }).catch(() => {});
      const m = await page.evaluate(() => {
        const n = performance.getEntriesByType('navigation')[0], f = performance.getEntriesByName('first-contentful-paint')[0];
        return {
          htmlBytes: n.decodedBodySize, dclMs: Math.round(n.domContentLoadedEventEnd), fcpMs: f ? Math.round(f.startTime) : null,
          csp: window.__csp || [], pill: document.getElementById('state').textContent,
          empty: !document.getElementById('sempty').hidden, view: location.hash,
        };
      });
      metrics.cold = { ...m, requests: [...paths] };
      check('console errors on load', errors.length === 0, errors);
      check('policy violations on load', m.csp.length === 0, m.csp);
      await fits(page, 'cold load');
      check('page weight', m.htmlBytes <= PAGE_BUDGET, `${m.htmlBytes} bytes, budget ${PAGE_BUDGET}`);
      check('cold load asks only for the page, health, the scan list and icon', paths.every(p => ['/', '/api/health', '/api/scans', '/favicon.svg'].includes(p)) && paths.includes('/api/scans'), paths);
      check('server shown online', m.pill === 'online', m.pill);
      check('the scan list opens first and says there are no scans yet', m.empty, m);

      // A tab with nothing running that comes back into view asks for health and nothing else.
      const again = await tabReturns(page, 3);
      metrics.tabReturns = { returns: 3, requests: again };
      check('a returning tab asks only for health', again.length === 3 && again.every(p => p === '/api/health'), again);

      // About loads the module list and the command contract once.
      const asked = [];
      page.on('request', r => asked.push(new URL(r.url()).pathname));
      await page.goto(base + '/#/about', { waitUntil: 'networkidle' });
      await page.waitForFunction(() => ['modules', 'command'].every(id => document.getElementById(id).textContent !== '…'), null, { timeout: 5000 }).catch(() => {});
      await page.goto(base + '/#/scans', { waitUntil: 'networkidle' });
      await page.goto(base + '/#/about', { waitUntil: 'networkidle' });
      check('About loads its details once', asked.filter(p => p === '/api/modules').length === 1 && asked.filter(p => p === '/api/command').length === 1, asked);
      check('About shows the module count', /^\d+$/.test(await page.textContent('#smodules')), await page.textContent('#smodules'));
      // The old addresses still land somewhere: #/lookup is New Scan, #/status is About.
      await page.goto(base + '/#/lookup', { waitUntil: 'networkidle' });
      check('#/lookup opens New Scan', await page.isVisible('#view-newscan'), 'hidden');
      await ctx.close();
    }

    // Both system themes: colours, the browser bar, contrast in every view, the scan flows.
    for (const scheme of ['dark', 'light']) {
      const ctx = await browser.newContext({ ...PHONE, colorScheme: scheme });
      const page = await ctx.newPage();
      const errors = [];
      page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
      page.on('pageerror', e => errors.push(String(e)));
      page.on('dialog', d => d.accept());
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      const look = () => page.evaluate(() => ({ bg: getComputedStyle(document.body).backgroundColor, bar: document.querySelector('meta[name=theme-color]').content }));
      const first = await look();
      const lightBg = 'rgb(238, 241, 244)', darkBg = 'rgb(10, 13, 17)';
      check(`${scheme}: page follows the system theme`, first.bg === (scheme === 'light' ? lightBg : darkBg), first);
      check(`${scheme}: browser bar matches the app bar`, first.bar === (scheme === 'light' ? '#ffffff' : '#11151b'), first);
      await audit(page, `${scheme} scans`);

      // New Scan: Spiderfoot's three ways of choosing what runs, each listing what the server has.
      await page.goto(base + '/#/newscan', { waitUntil: 'networkidle' });
      await audit(page, `${scheme} new scan`);
      await page.click('#nt-modules');
      await page.waitForSelector('#modlist tr');
      const modules = (await api(page, '/api/modules')).modules;
      check(`${scheme}: By Module lists every module`, (await page.$$('#modlist tr')).length === modules.length, `${(await page.$$('#modlist tr')).length} of ${modules.length}`);
      await audit(page, `${scheme} new scan by module`);
      await page.click('#nt-types');
      await page.waitForSelector('#typelist label');
      const types = await api(page, '/api/eventtypes');
      check(`${scheme}: By Required Data lists every data type`, (await page.$$('#typelist input')).length === types.length, `${(await page.$$('#typelist input')).length} of ${types.length}`);
      await audit(page, `${scheme} new scan by data`);

      const run = await newScan(page, `check ${scheme}`, 1);
      metrics[`${scheme}ScanMs`] = run.ms;
      check(`${scheme}: the scan finishes`, run.status === 'FINISHED', run);
      const id = run.id, root = '/api/scans/' + encodeURIComponent(id);
      const [row, summary, elements, correlations, graph, log] = await Promise.all(['', '/summary', '/elements', '/correlations', '/graph', '/log'].map(p => api(page, root + p)));
      metrics[`${scheme}Scan`] = { elements: elements.length, types: summary.length, correlations: correlations.length, nodes: graph.nodes.length, log: log.length };
      check(`${scheme}: the scan found something`, elements.length > 0, metrics[`${scheme}Scan`]);

      // Summary: Spiderfoot's counters and one bar per data type.
      await page.waitForFunction(() => document.getElementById('ctotal').textContent !== '?');
      const shown = await page.evaluate(() => ({ total: +document.getElementById('ctotal').textContent, unique: +document.getElementById('cunique').textContent, bars: document.querySelectorAll('#bars .bar').length, status: document.getElementById('cstatus').textContent }));
      check(`${scheme}: Summary counts every element`, shown.total === summary.reduce((n, t) => n + t.total, 0) && shown.unique === summary.reduce((n, t) => n + t.unique, 0) && shown.status === row.status, { shown, summary });
      check(`${scheme}: Summary has a bar per data type`, shown.bars === summary.length, shown);
      await audit(page, `${scheme} summary`);

      // Browse: the data types, then one type's elements with the full raw record behind each.
      await page.click('#sctabs a[data-tab=browse]');
      await page.waitForSelector('#types tr a');
      check(`${scheme}: Browse lists every data type`, (await page.$$('#types tr')).length === summary.length, summary.length);
      await audit(page, `${scheme} browse`);
      await page.click('#types tr a >> nth=0');
      await page.waitForSelector('#bbody tbody tr');
      const type = decodeURIComponent((await page.evaluate(() => location.hash)).split('/')[4] || '');
      const ofType = elements.filter(e => e.type === type);
      check(`${scheme}: Browse shows every element of a type`, (await page.$$('#bbody tbody tr')).length === Math.min(200, ofType.length) && ofType.length > 0, `${type}: ${(await page.$$('#bbody tbody tr')).length} of ${ofType.length}`);
      await page.click('#bbody details.raw summary >> nth=0');
      await page.waitForSelector('#bbody details.raw[open] .ent-b', { timeout: 3000 }).catch(() => {});
      check(`${scheme}: an element opens to its raw record`, await page.isVisible('#bbody details.raw[open] .ent-b'), 'closed');
      await audit(page, `${scheme} browse type`);
      await page.click('#bpath');
      await page.waitForSelector('#bbody .tree li', { timeout: 5000 }).catch(() => {});
      const leaves = await page.$$eval('#bbody .tree li.hit > .data', l => new Set(l.map(e => e.textContent)).size);
      check(`${scheme}: Discovery Path places every element of the type`, leaves === new Set(ofType.map(e => String(e.data))).size, `${leaves} of ${new Set(ofType.map(e => String(e.data))).size}`);
      await audit(page, `${scheme} discovery path`);
      await page.click('#bfull');
      await page.check('#bbody tbody tr >> nth=0 >> input[type=checkbox]');
      await page.click('#bsetfp');
      await page.waitForSelector('#bbody .label.warn', { timeout: 5000 }).catch(() => {});
      const marked = (await api(page, root + '/elements?type=' + encodeURIComponent(type))).filter(e => e.fp);
      check(`${scheme}: an element can be marked a false positive`, marked.length === 1 && await page.isVisible('#bbody .label.warn'), marked.length);

      // Correlations, Graph, Scan Settings and Log, each as the API holds them.
      await page.click('#sctabs a[data-tab=correlations]');
      await page.waitForSelector('#corrs tr');
      check(`${scheme}: Correlations lists every correlation`, correlations.length ? (await page.$$('#corrs details')).length === correlations.length : (await page.$$('#corrs td.none')).length === 1, correlations.length);
      await audit(page, `${scheme} correlations`);
      // Spiderfoot's sf.py -C from the page: every rule again over the saved elements.
      await page.click('#recorrelate');
      await page.waitForFunction(() => /re-run/i.test(document.getElementById('cnote').textContent), null, { timeout: 10000 }).catch(() => {});
      const rerun = await api(page, root + '/correlations');
      check(`${scheme}: Re-run Correlations reruns the rules`, (await page.textContent('#cnote')).includes(`${rerun.length} found`), await page.textContent('#cnote'));
      await page.click('#cexport summary');
      const [cdownload] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#cexport button[data-cformat=csv]')]);
      check(`${scheme}: correlations export as CSV`, cdownload.suggestedFilename().endsWith('.csv') && fs.readFileSync(await cdownload.path(), 'utf8').startsWith('Rule Name,Correlation,Risk'), cdownload.suggestedFilename());
      await page.click('#sctabs a[data-tab=graph]');
      await page.waitForSelector('#gnodes circle', { timeout: 5000 }).catch(() => {});
      check(`${scheme}: Graph draws every node`, (await page.$$('#gnodes circle')).length === graph.nodes.length, `${(await page.$$('#gnodes circle')).length} of ${graph.nodes.length}`);
      await audit(page, `${scheme} graph`);
      await page.click('#sctabs a[data-tab=settings]');
      await page.waitForFunction(t => document.getElementById('meta').textContent.includes(t), TARGET, { timeout: 3000 }).catch(() => {});
      check(`${scheme}: Scan Settings names the target`, (await page.textContent('#meta')).includes(TARGET), await page.textContent('#meta'));
      // The depth New Scan asked for, why the scan stopped following what it found, and each
      // lookup it ran with what that lookup found.
      const opts = await page.textContent('#opts');
      check(`${scheme}: Scan Settings shows the depth and why the scan stopped`, row.options.depth === 1 && opts.includes('1 hop past the target') && typeof row.termination === 'string' && opts.includes(row.termination + ':'), { opts, depth: row.options.depth, termination: row.termination });
      check(`${scheme}: the Discovery Tree lists each lookup and what it found`, row.lineage.length > 0 && (await page.$$('#lineage tbody tr')).length === Math.min(200, row.lineage.length) && (await page.textContent('#lineage-n')) === String(row.lineage.length), `${(await page.$$('#lineage tbody tr')).length} of ${row.lineage.length}`);
      await audit(page, `${scheme} scan settings`);
      await page.click('#sctabs a[data-tab=log]');
      await page.waitForSelector('#log tr');
      // Read again: re-running the correlations logged an entry of its own.
      const logged = await api(page, root + '/log');
      check(`${scheme}: Log shows every entry`, logged.length > log.length && (await page.$$('#log tr')).length === logged.length, `${(await page.$$('#log tr')).length} of ${logged.length}`);
      await audit(page, `${scheme} log`);

      // Search across the scan, Spiderfoot's wildcard form, for the middle of an element it holds.
      const probe = elements.map(e => String(e.data)).filter(d => d.length > 2 && !/[\n*]/.test(d)).sort((a, b) => a.length - b.length)[0] || TARGET;
      await page.fill('#scq', '*' + probe.slice(1, -1) + '*');
      await page.click('#scsearch button');
      await page.waitForSelector('#pane-search:not([hidden])');
      check(`${scheme}: a wildcard search finds the element`, (await page.$$('#sresults tbody tr')).length > 0, `${probe}: ${await page.textContent('#shits')}`);
      await audit(page, `${scheme} search`);

      // Export: CSV as Spiderfoot names it, an Excel workbook, and JSON with every element.
      await page.click('#sctabs a[data-tab=summary]');
      for (const format of ['csv', 'xlsx', 'json']) {
        await page.click('#scexport summary');
        const [download] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click(`#scexport button[data-format=${format}]`)]);
        const body = fs.readFileSync(await download.path(), format === 'xlsx' ? 'latin1' : 'utf8');
        // An Excel workbook is a zip: it opens with the local file header's PK signature.
        if (format === 'xlsx') check(`${scheme}: Excel export saves a workbook`, download.suggestedFilename().endsWith('.xlsx') && body.startsWith('PK\x03\x04'), download.suggestedFilename());
        else if (format === 'csv') check(`${scheme}: CSV export saves the elements`, download.suggestedFilename().endsWith('.csv') && body.split('\n').filter(Boolean).length > elements.length, download.suggestedFilename());
        else { let parsed = null; try { parsed = JSON.parse(body); } catch (_) {} check(`${scheme}: JSON export saves the scan`, parsed !== null && download.suggestedFilename().endsWith('.json'), download.suggestedFilename()); }
      }

      // The toggle overrides the system theme and is remembered; a reload (Android discarding the
      // tab) comes back to the same section of the same saved scan.
      await page.click('#sctabs a[data-tab=browse]');
      await page.waitForSelector('#types tr a');
      await page.click('#theme');
      const flipped = await look();
      check(`${scheme}: toggle flips the theme`, flipped.bg === (scheme === 'light' ? darkBg : lightBg) && flipped.bar === (scheme === 'light' ? '#11151b' : '#ffffff'), flipped);
      await audit(page, `${scheme} toggled`);
      await page.reload({ waitUntil: 'networkidle' });
      check(`${scheme}: toggled theme survives a reload`, (await look()).bg === flipped.bg, await look());
      await page.waitForSelector('#types tr a', { timeout: 5000 }).catch(() => {});
      check(`${scheme}: a reload comes back to the scan's Browse`, (await page.$$('#types tr')).length === summary.length, await page.evaluate(() => location.hash));
      const back = await tabReturns(page, 3);
      check(`${scheme}: a finished scan's returning tab asks only for health`, back.length === 3 && back.every(p => p === '/api/health'), back);

      // Analysis through the form, kept for the tab across a reload.
      await page.goto(base + '/#/analyze', { waitUntil: 'networkidle' });
      await page.fill('#seeds', SEEDS);
      const t = Date.now();
      await page.click('#arun');
      await page.waitForSelector('#aresult:not([hidden])', { timeout: 20000 });
      metrics[`${scheme}AnalyzeMs`] = Date.now() - t;
      check(`${scheme}: analysis lists entities`, (await page.$$('#aentities tr')).length >= 6, 'too few rows');
      await audit(page, `${scheme} analysis`);
      await page.reload({ waitUntil: 'networkidle' });
      check(`${scheme}: analysis survives a reload`, await page.evaluate(() => !document.getElementById('aresult').hidden), 'analysis hidden');

      // The scan list, Settings and About.
      await page.goto(base + '/#/scans', { waitUntil: 'networkidle' });
      await page.waitForSelector('#scans tr');
      const listed = await api(page, '/api/scans');
      check(`${scheme}: the scan list shows every saved scan`, (await page.$$('#scans tr')).length === listed.length && listed.some(s => s.id === id && s.elements === elements.length), listed.map(s => [s.id, s.status, s.elements]));
      // Every scan selected, then Spiderfoot's multi-scan export as one workbook.
      await page.check('#sall');
      await page.click('#sexport summary');
      const menu = await page.evaluate(() => { const r = document.querySelector('#sexport .menu-list').getBoundingClientRect(); return { left: r.left, right: r.right, width: document.documentElement.clientWidth }; });
      check(`${scheme}: an open export menu stays on the screen`, menu.left >= 0 && menu.right <= menu.width, menu);
      const [many] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#sexport button[data-mformat=xlsx]')]);
      check(`${scheme}: the selected scans export as one workbook`, many.suggestedFilename().endsWith('.xlsx') && fs.readFileSync(await many.path(), 'latin1').startsWith('PK\x03\x04'), many.suggestedFilename());
      await page.uncheck('#sall');
      await audit(page, `${scheme} scans`);
      await page.goto(base + '/#/settings', { waitUntil: 'networkidle' });
      await page.waitForSelector('#mods tr');
      check(`${scheme}: Settings lists every module`, (await page.$$('#mods tr')).length === modules.length, (await page.$$('#mods tr')).length);
      const rules = await api(page, '/api/correlationrules');
      await page.waitForSelector('#rules tr', { timeout: 5000 }).catch(() => {});
      check(`${scheme}: Settings lists every correlation rule`, rules.length > 0 && (await page.$$('#rules tr')).length === rules.length, `${(await page.$$('#rules tr')).length} of ${rules.length}`);
      await audit(page, `${scheme} settings`);
      await page.goto(base + '/#/about', { waitUntil: 'networkidle' });
      await audit(page, `${scheme} about`);

      // Clone fills New Scan from the scan; Re-run makes a new scan of the same target with the
      // same options; Delete removes it and everything it found.
      if (scheme === 'dark') {
        await page.goto(base + '/#/scan/' + encodeURIComponent(id) + '/summary', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => document.getElementById('scstatus').textContent === 'FINISHED', null, { timeout: 5000 }).catch(() => {});
        await page.click('#scclone');
        await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 }).catch(() => {});
        const cloned = await page.evaluate(() => ({ name: document.getElementById('sname').value, target: document.getElementById('starget').value, kind: document.getElementById('skind').value, depth: document.getElementById('sdepth').value, usecase: document.querySelector('input[name=usecase]:checked').value }));
        check('Clone fills New Scan from the scan', cloned.name === row.name && cloned.target === TARGET && cloned.kind === row.kind && cloned.depth === '1' && cloned.usecase === row.options.usecase, cloned);
        await audit(page, 'dark cloned new scan');
        await page.goto(base + '/#/scan/' + encodeURIComponent(id) + '/summary', { waitUntil: 'networkidle' });
        await page.click('#screrun');
        await page.waitForFunction(was => location.hash.split('/')[2] && decodeURIComponent(location.hash.split('/')[2]) !== was, id, { timeout: 10000 }).catch(() => {});
        const again = decodeURIComponent((await page.evaluate(() => location.hash)).split('/')[2]);
        await page.waitForFunction(() => ['FINISHED', 'ABORTED', 'ERROR-FAILED'].includes(document.getElementById('scstatus').textContent), null, { timeout: 90000 }).catch(() => {});
        const rerun = await api(page, '/api/scans/' + encodeURIComponent(again));
        check('Re-run makes a new scan of the same target', again !== id && rerun.target === TARGET && rerun.status === 'FINISHED' && rerun.options.depth === 1, rerun);
        // Compare, which Spiderfoot lacks: from the re-run, the scan of the same target before it.
        await page.click('#sccompare');
        await page.waitForFunction(() => !document.getElementById('view-compare').hidden && !/^Comparing/.test(document.getElementById('cmpmeta').textContent), null, { timeout: 10000 }).catch(() => {});
        const pair = encodeURIComponent(id) + '/' + encodeURIComponent(again);
        const compared = await api(page, '/api/scans/compare?ids=' + encodeURIComponent(id + ',' + again));
        const shownCompare = await page.evaluate(() => ({ hash: location.hash, meta: document.getElementById('cmpmeta').textContent, types: document.querySelectorAll('#cmptypes tr').length, added: document.getElementById('cmpadd-n').textContent, removed: document.getElementById('cmprem-n').textContent }));
        check('Compare opens on the earlier scan of the same target', shownCompare.hash === '#/compare/' + pair, shownCompare.hash);
        check('Compare shows what the API compares', shownCompare.types === Math.max(1, compared.types.length) && shownCompare.added === String(compared.added.length) && shownCompare.removed === String(compared.removed.length) && shownCompare.meta.includes('No change') === compared.unchanged, { shownCompare, types: compared.types.length, added: compared.added.length, removed: compared.removed.length, unchanged: compared.unchanged });
        await audit(page, 'dark compare');
        await page.click('#cmpexport summary');
        const [xdownload] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#cmpexport button[data-xformat=csv]')]);
        check('a comparison exports as CSV', xdownload.suggestedFilename().endsWith('.csv') && fs.readFileSync(await xdownload.path(), 'utf8').startsWith('Change,Scan Name,Updated,Type'), xdownload.suggestedFilename());
        // From Scans: two selected scans compare, the earlier first whatever the order picked.
        await page.goto(base + '/#/scans', { waitUntil: 'networkidle' });
        await page.waitForSelector('#scans tr');
        for (const pick of [again, id]) await page.locator('#scans span.pick', { has: page.locator(`a[href="#/scan/${encodeURIComponent(pick)}"]`) }).locator('input').check();
        check('Compare needs exactly two scans selected', await page.isEnabled('#scompare'), 'disabled with two selected');
        await page.click('#scompare');
        await page.waitForFunction(() => location.hash.startsWith('#/compare/'), null, { timeout: 5000 }).catch(() => {});
        check('Scans compares the two selected, the earlier first', (await page.evaluate(() => location.hash)) === '#/compare/' + pair, await page.evaluate(() => location.hash));
        await page.goto(base + '/#/scan/' + encodeURIComponent(again) + '/summary', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => document.getElementById('scstatus').textContent === 'FINISHED', null, { timeout: 5000 }).catch(() => {});
        await page.click('#scdelete');
        await page.waitForFunction(() => location.hash === '#/scans', null, { timeout: 10000 }).catch(() => {});
        const left = await api(page, '/api/scans');
        check('Delete removes the scan', !left.some(s => s.id === again) && left.some(s => s.id === id), left.map(s => s.id));
      }
      check(`${scheme}: no console errors`, errors.length === 0, errors);
      kept = (await api(page, '/api/scans')).length;
      await ctx.close();
    }

    // A stopped server is named, with the command that starts it; its return is noticed without
    // a reload, and the saved scans are all still there.
    {
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      await page.waitForSelector('#scans tr');
      await stop();
      await page.click('#srefresh');
      await page.waitForSelector('#serror:not([hidden])', { timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(300);
      const down = { error: await page.textContent('#serror'), pill: await page.textContent('#state') };
      metrics.serverDown = down;
      check('a stopped server is named with the command that starts it', /huntsman start/.test(down.error) && down.pill === 'offline', down);
      await serve(new URL(base).host);
      await page.waitForFunction(() => document.getElementById('state').textContent === 'online', null, { timeout: 9000 }).catch(() => {});
      check('the page notices the server is back', (await page.textContent('#state')) === 'online', await page.textContent('#state'));
      await page.click('#srefresh');
      await page.waitForFunction(() => document.getElementById('serror').hidden, null, { timeout: 5000 }).catch(() => {});
      check('saved scans survive a server restart', (await page.$$('#scans tr')).length === kept && kept > 0, `${(await page.$$('#scans tr')).length} of ${kept}`);
      await ctx.close();
    }
  } catch (error) {
    failures.push('run: ' + (error && error.stack || error));
  } finally {
    await browser.close();
    await stop();
    fs.rmSync(home, { recursive: true, force: true });
  }
  console.log(JSON.stringify({ base, metrics, failures }, null, 1));
  if (failures.length) { process.stderr.write(`web-ui-check: ${failures.length} check(s) failed\n- ${failures.join('\n- ')}\n`); process.exit(1); }
  process.stderr.write('web-ui-check: all checks passed\n');
})();
