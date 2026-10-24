#!/usr/bin/env node
// The serve web UI in a phone's browser, checked end to end. It starts `huntsman-recon serve` on a
// free loopback port, drives the page at 360x740 with touch in both system themes, and fails when
// a behaviour the page promises does not hold: it loads with no console error or policy
// violation, fits the screen with 44 px targets, passes axe-core's WCAG 2.2 AA rules in every
// view of both themes, runs a scan one hop deep from New Scan to FINISHED and shows exactly what
// the scan API holds in its Summary, Browse, Correlations, Graph, Scan Settings and Log sections,
// marks a false positive, searches, exports, clones, re-runs, compares and deletes a scan,
// searches every scan, starts a scan of a value it found, keeps its place across a reload, asks
// only for health when a tab with nothing running comes back, asks to be reloaded when the
// server was upgraded under it, keeps a big scan's Graph answering on a throttled CPU, says what
// to do when the server stops, notices when it is back, and finds the saved scans still there
// after the restart. It reads a picked file's embedded metadata in Inspect, only when asked.
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
// Two additional KiB accommodate the complete, lossless on-demand TXT exporter.
const PAGE_BUDGET = 128 * 1024;
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
// The Graph draws each element as a dot, a round-capped subpath of no length, in its data type's
// path; the rim under them and the chosen element's ring are drawn again and not counted. Answers
// the count, or with `want` whether the count is that.
const DOTS = want => { const n = [...document.querySelectorAll('#gnodes path:not(.grim,.gring,.gpick)')].reduce((n, p) => n + ((p.getAttribute('d') || '').match(/M/g) || []).length, 0); return want === undefined ? n : n === want; };

(async () => {
  const base = await serve('127.0.0.1:0');
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || process.env.CHROME_BIN || undefined });
  const api = async (page, p) => (await page.request.get(base + p, { headers: LH })).json();
  // Runs a scan through New Scan, following what it finds `depth` hops, and waits for it to
  // finish; answers its id and how long it took.
  async function newScan(page, name, depth) {
    await page.goto(base + '/#/newscan', { waitUntil: 'networkidle' });
    await page.fill('#starget', TARGET);
    // The browser preserves the last chosen scan kind. Each independent
    // acceptance scan specifies auto so a prior network pivot cannot bleed in.
    await page.selectOption('#skind', 'auto');
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

    // A tab open across an upgrade: once health names another page than the one the tab loaded,
    // the page asks to be reloaded, and Reload brings the page the server now serves.
    {
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      const own = await page.evaluate(() => document.querySelector('meta[name=huntsman-page]').content);
      const served = (await api(page, '/api/health')).page;
      check('the page carries the page id health names', /^[0-9a-f]{16}$/.test(own) && own === served, { own, served });
      check('a tab on the page the server serves does not ask to reload', await page.isHidden('#upgraded'), 'shown');
      await page.route('**/api/health', async route => {
        const answer = await route.fetch();
        await route.fulfill({ response: answer, json: { ...(await answer.json()), page: '0000000000000000' } });
      });
      await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange')); });
      await page.waitForSelector('#upgraded:not([hidden])', { timeout: 5000 }).catch(() => {});
      check('a tab whose server was upgraded asks to reload', await page.isVisible('#upgraded'), 'hidden');
      await audit(page, 'upgraded tab');
      await page.unroute('**/api/health');
      await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle' }), page.click('#reload')]);
      check('Reload brings the page the server serves', await page.isHidden('#upgraded'), 'still shown');
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

      // Synthetic OS-cache fixture ONLY for browser rendering. Separate Rust HTTP
      // tests cover missing Termux:API, refusal and actual server response codes.
      const radarFixture = {
        source: 'termux-wifi-scaninfo', acquisition: 'android_cached_scan_results_not_active_scan',
        status: 'stale_only', observed: 1, rejected: 0,
        observations: [{
          sighting: { network_id: '3c:5a:b4:11:22:33', name: 'fixture', signal_dbm: -58, encryption: '[WPA2-PSK-CCMP][ESS]' },
          band: '5GHz', frequency_mhz: 5180, channel_bandwidth_mhz: '80', capabilities: '[WPA2-PSK-CCMP][ESS]',
          os_timestamp_us: 1234567890, age_secs: 900, freshness: 'stale'
        }]
      };
      let radarCalls = 0, lookupHeader = false;
      const countRadar = request => { if (new URL(request.url()).pathname === '/api/radar/wifi') radarCalls++; };
      page.on('request', countRadar);
      await page.route('**/api/radar/wifi', async route => {
        lookupHeader = route.request().headers()['x-huntsman-lookup'] === '1';
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(radarFixture) });
      });
      await page.goto(base + '/#/radar', { waitUntil: 'networkidle' });
      check(`${scheme}: Radar is a reachable mobile view`, await page.isVisible('#view-radar'), 'missing');
      check(`${scheme}: Radar never queries the sensor merely because it opened`, radarCalls === 0, radarCalls);
      await audit(page, `${scheme} radar`);
      await page.click('#rread');
      await page.waitForSelector('#rresult:not([hidden])', { timeout: 10000 }).catch(() => {});
      check(`${scheme}: Radar requests an OS-cache observation only once after explicit action`,
        radarCalls === 1 && lookupHeader, { radarCalls, lookupHeader });
      const radarText = await page.textContent('#rrows');
      check(`${scheme}: Radar shows cached values and stale labels without inventing positions`,
        await page.isHidden('#rerror') && radarText.includes('3c:5a:b4:11:22:33') &&
        radarText.includes('900') && radarText.includes('stale') && await page.isEnabled('#rdownload'),
        radarText);
      check(`${scheme}: Radar shows every observation field the adapter fills, not only the coarse band`,
        radarText.includes('5180') && radarText.includes('80') && radarText.includes('[WPA2-PSK-CCMP][ESS]') &&
        radarText.includes('1234567890'), radarText);
      const [radarDownload] = await Promise.all([
        page.waitForEvent('download', { timeout: 10000 }), page.click('#rdownload')
      ]);
      const exported = JSON.parse(fs.readFileSync(await radarDownload.path(), 'utf8'));
      check(`${scheme}: exported Wi-Fi cache preserves source and uncertainty`,
        exported.source === 'termux-wifi-scaninfo' && exported.status === 'stale_only' &&
        exported.observations[0].age_secs === 900, exported);

      // A local cached BSSID is a lead for Huntsman's existing network lookup,
      // not permission to spend network egress or operator keys automatically.
      let radarScanPosts = 0;
      const countScanPost = request => {
        if (new URL(request.url()).pathname === '/api/scans' && request.method() === 'POST') radarScanPosts++;
      };
      page.on('request', countScanPost);
      await page.click('#rrows button');
      await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 });
      const handoff = await page.evaluate(() => ({
        target: document.getElementById('starget').value,
        kind: document.getElementById('skind').value,
        depth: document.getElementById('sdepth').value,
        name: document.getElementById('sname').value
      }));
      check(`${scheme}: Radar BSSID pivots into a prefilled NETWORK scan, not a geolocation`,
        handoff.target === '3c:5a:b4:11:22:33' && handoff.kind === 'network' &&
        handoff.depth === '0' && handoff.name.includes('3c:5a:b4:11:22:33'), handoff);
      check(`${scheme}: investigating a cached BSSID does not automatically run a scan`,
        radarScanPosts === 0, radarScanPosts);
      page.off('request', countScanPost);
      await page.unroute('**/api/radar/wifi');
      page.off('request', countRadar);

      // The cells Android reports and the track log, read from the same tab on a press only.
      const cellsFixture = {
        source: 'termux-telephony-cellinfo', acquisition: 'android_cached_cellinfo_not_active_scan',
        status: 'freshness_unknown', observed: 2, rejected: 0,
        observations: [
          { sighting: { network_id: 'gsm:505-01-17-91', signal_dbm: -83 }, technology: 'gsm', mcc: '505', mnc: '01', area_code: 17, cell_id: 91, registered: true, freshness: 'unknown' },
          { sighting: { network_id: 'lte:505-01-19-12345', signal_dbm: -101 }, technology: 'lte', mcc: '505', mnc: '01', area_code: 19, cell_id: 12345, registered: false, freshness: 'unknown' }
        ]
      };
      const trackFixture = {
        sweeps: 3, located_sweeps: 3, distinct_cells: 3, skipped_lines: 0,
        recurring: [{ mac: '3c:5a:b4:11:22:33', name: null, vendor: null, device_class: null, sweeps_seen: 3, first_ts: 1700000000, last_ts: 1700001200 }],
        followers: [{ mac: '3c:5a:b4:11:22:33', vendor: null, device_class: null, distinct_cells: 3, sightings: 3, coverage: 1, first_ts: 1700000000, last_ts: 1700001200, span_secs: 1200 }]
      };
      let cellCalls = 0, trackCalls = 0, trackMethod = '', sensorHeaders = true;
      const countSensors = request => {
        const path = new URL(request.url()).pathname;
        if (path === '/api/radar/cells') { cellCalls++; sensorHeaders &&= request.headers()['x-huntsman-lookup'] === '1'; }
        if (path === '/api/radar/track') { trackCalls++; trackMethod = request.method(); sensorHeaders &&= request.headers()['x-huntsman-lookup'] === '1'; }
      };
      page.on('request', countSensors);
      await page.route('**/api/radar/cells', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cellsFixture) }));
      await page.route('**/api/radar/track', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(trackFixture) }));
      await page.goto(base + '/#/radar', { waitUntil: 'networkidle' });
      check(`${scheme}: Radar reads no cells and logs no sweep merely because it opened`, cellCalls === 0 && trackCalls === 0, { cellCalls, trackCalls });
      await page.click('#rcread');
      await page.waitForSelector('#rcresult:not([hidden])', { timeout: 10000 }).catch(() => {});
      const cellsText = await page.textContent('#rcrows');
      check(`${scheme}: Radar shows the cells Android reports, registered state and signal, with no position`,
        cellCalls === 1 && sensorHeaders && await page.isHidden('#rerror') && cellsText.includes('gsm:505-01-17-91') &&
        cellsText.includes('lte:505-01-19-12345') && cellsText.includes('yes') && cellsText.includes('-83') &&
        (await page.textContent('#rcsummary')).includes('termux-telephony-cellinfo'), cellsText);
      await page.click('#rcrows button');
      await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 });
      const cellHandoff = await page.evaluate(() => ({
        target: document.getElementById('starget').value, kind: document.getElementById('skind').value,
        depth: document.getElementById('sdepth').value
      }));
      check(`${scheme}: a reported cell pivots into a prefilled cell: NETWORK scan`,
        cellHandoff.target === 'cell:505:01:17:91' && cellHandoff.kind === 'network' && cellHandoff.depth === '0', cellHandoff);
      await page.goto(base + '/#/radar', { waitUntil: 'networkidle' });
      await page.click('#rtrack');
      await page.waitForSelector('#rtresult:not([hidden])', { timeout: 10000 }).catch(() => {});
      const trackText = await page.textContent('#rtrows');
      check(`${scheme}: one press logs one sweep by POST and shows the follower and recurring devices`,
        trackCalls === 1 && trackMethod === 'POST' && sensorHeaders && await page.isHidden('#rerror') &&
        trackText.includes('3c:5a:b4:11:22:33') && trackText.includes('1.00') && trackText.includes('1200') &&
        (await page.textContent('#rrrows')).includes('3c:5a:b4:11:22:33') &&
        (await page.textContent('#rtsummary')).includes('sweeps: 3') &&
        (await page.textContent('#rstatus')).includes('travelled with you'), { trackCalls, trackMethod, trackText });
      page.off('request', countSensors);
      await page.unroute('**/api/radar/cells');
      await page.unroute('**/api/radar/track');

      // Inspect: a picked file goes to this server's own exif and docmeta readers, only on request.
      // The file is a JPEG carrying an XMP packet with an edit history and a GPS position.
      const xmp = '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description rdf:about="" ' +
        'xmp:CreatorTool="Fixture Camera 2" exif:GPSLatitude="48,51.00N" exif:GPSLongitude="2,20.00E">' +
        '<xmpMM:History><rdf:Seq><rdf:li stEvt:action="created" stEvt:softwareAgent="Fixture Editor"/>' +
        '</rdf:Seq></xmpMM:History></rdf:Description></rdf:RDF></x:xmpmeta>';
      const photo = Buffer.concat([Buffer.from([0xff, 0xd8]), Buffer.from(xmp), Buffer.from([0xff, 0xd9])]);
      let inspectCalls = 0;
      const countInspect = request => { if (new URL(request.url()).pathname === '/api/inspect') inspectCalls++; };
      page.on('request', countInspect);
      await page.goto(base + '/#/inspect', { waitUntil: 'networkidle' });
      check(`${scheme}: Inspect is a reachable mobile view`, await page.isVisible('#view-inspect'), 'missing');
      check(`${scheme}: Inspect sends nothing merely because it opened`, inspectCalls === 0, inspectCalls);
      await audit(page, `${scheme} inspect`);
      await page.setInputFiles('#ifile', { name: 'holiday.jpg', mimeType: 'image/jpeg', buffer: photo });
      await page.click('#irun');
      await page.waitForSelector('#iresult:not([hidden])', { timeout: 10000 }).catch(() => {});
      const fieldsText = await page.textContent('#ifields');
      const entitiesText = await page.textContent('#ientities');
      check(`${scheme}: Inspect reads the picked file's embedded metadata once`,
        inspectCalls === 1 && await page.isHidden('#ierror') &&
        fieldsText.includes('Fixture Camera 2') && fieldsText.includes('Fixture Editor') &&
        fieldsText.includes('file_sha256') && fieldsText.includes('file_size_bytes') &&
        entitiesText.includes('holiday.jpg') && entitiesText.includes('48.850000,2.333333'),
        { inspectCalls, fieldsText, entitiesText, error: await page.textContent('#ierror') });
      const claimsText = await page.textContent('#iclaims');
      const reportText = await page.textContent('#ireport');
      const stamped = /\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/;
      check(`${scheme}: Inspect shows each reader's claim, when it was recorded, and the whole report`,
        claimsText.includes('holiday.jpg with') && claimsText.includes('docmeta') && stamped.test(claimsText) &&
        stamped.test(fieldsText) && stamped.test(entitiesText) && entitiesText.includes('docmeta') &&
        reportText.includes('holiday.jpg') && reportText.includes('Fixture Camera 2'),
        { claimsText, entitiesText: entitiesText.slice(0, 200), report: reportText.length });
      await audit(page, `${scheme} inspect result`);
      await page.setInputFiles('#ifile', []);
      await page.click('#irun');
      const refusedStatus = await page.textContent('#istatus');
      check(`${scheme}: a file the page refuses itself marks the tables as the previous file's`,
        inspectCalls === 1 && refusedStatus.includes('PREVIOUS') &&
        (await page.textContent('#ierror')).includes('Choose a file'),
        { inspectCalls, refusedStatus });
      let inspectScanPosts = 0;
      const countInspectScan = request => {
        if (new URL(request.url()).pathname === '/api/scans' && request.method() === 'POST') inspectScanPosts++;
      };
      page.on('request', countInspectScan);
      await page.click('#ientities button');
      await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 });
      const located = await page.evaluate(() => ({
        target: document.getElementById('starget').value, kind: document.getElementById('skind').value
      }));
      check(`${scheme}: an embedded GPS position pivots into a prefilled network scan, unstarted`,
        located.target === '48.850000,2.333333' && located.kind === 'network' && inspectScanPosts === 0,
        { located, inspectScanPosts });
      page.off('request', countInspectScan);
      page.off('request', countInspect);

      // New Scan: Spiderfoot's three ways of choosing what runs, each listing what the server has.
      await page.goto(base + '/#/newscan', { waitUntil: 'networkidle' });
      await audit(page, `${scheme} new scan`);
      await page.click('#nt-modules');
      await page.waitForSelector('#modlist tr');
      const modules = (await api(page, '/api/modules')).modules;
      check(`${scheme}: By Module lists every module`, (await page.$$('#modlist tr')).length === modules.length, `${(await page.$$('#modlist tr')).length} of ${modules.length}`);
      const asked = (await api(page, '/api/settings')).modules;
      const boxes = await page.$$eval('#modlist input', l => l.map(i => ({ name: i.value, checked: i.checked, disabled: i.disabled })));
      const misticked = boxes.filter(b => { const m = asked.find(x => x.name === b.name); return !m || b.checked !== m.lookups.length > 0 || b.disabled !== !m.lookups.length; });
      check(`${scheme}: By Module ticks each module a scan lookup asks and closes the rest`, boxes.length === asked.length && boxes.some(b => b.checked) && !misticked.length, misticked.slice(0, 5));
      await audit(page, `${scheme} new scan by module`);
      const techniqueChoices = await page.$$eval('#nattackfocus option', l => l.map(x => x.value).filter(Boolean));
      const focusedTechnique = techniqueChoices.find(id => asked.some(m => (m.attack_techniques || []).includes(id) && m.lookups.length && m.configured !== false));
      check(`${scheme}: ATT&CK focus exposes executable technique mappings`, !!focusedTechnique, techniqueChoices.length);
      if (focusedTechnique) {
        await page.selectOption('#nattackfocus', focusedTechnique);
        await page.click('#nattackapply');
        const selected = await page.$$eval('#modlist input:checked', l => l.map(i => i.value).sort());
        const expected = asked.filter(m => m.lookups.length && m.configured !== false && (m.attack_techniques || []).includes(focusedTechnique)).map(m => m.name).sort();
        check(`${scheme}: ATT&CK focus changes real scan source admission`,
          selected.length > 0 && JSON.stringify(selected) === JSON.stringify(expected), { selected, expected });
        check(`${scheme}: ATT&CK selection is not submitted without confirmation`,
          await page.textContent('#nattackstatus') !== '', focusedTechnique);
      }
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
      const sourceCoverage = await page.textContent('#srcs-coverage');
      const expectedCoverage = row.source_execution_summary;
      check(`${scheme}: Summary shows recorded coverage without implying exhaustive discovery`,
        expectedCoverage && sourceCoverage.includes(expectedCoverage.accepted + ' of ' + expectedCoverage.total) &&
        sourceCoverage.includes(expectedCoverage.not_configured + ' not configured') &&
        sourceCoverage.includes('does not establish exhaustive source coverage'),
        { sourceCoverage, expectedCoverage });
      const observedShown = await page.evaluate(() => [...document.querySelectorAll('#srcs tr')].map(tr => tr.cells[2] ? tr.cells[2].textContent : ''));
      const observedWanted = await page.evaluate(sources => sources.map(o => when(o.observed_at_unix * 1000)), row.sources);
      check(`${scheme}: Summary shows when each source was queried`,
        row.sources.length > 0 && row.sources.every(o => o.observed_at_unix) &&
        JSON.stringify(observedShown) === JSON.stringify(observedWanted),
        { observedShown, observedWanted });
      const uncertainty = row.uncertainty_register;
      const shownUncertainty = await page.evaluate(() => ({
        total: document.getElementById('unc-n').textContent,
        rows: document.querySelectorAll('#uncrows tr').length,
        note: document.getElementById('uncnote').textContent,
        text: document.getElementById('uncrows').textContent
      }));
      check(`${scheme}: Uncertainty register exposes saved evidence and acknowledges discovery limits`,
        uncertainty && shownUncertainty.total === String(uncertainty.items.length) &&
        shownUncertainty.rows === Math.max(1, Math.min(200, uncertainty.items.length)) &&
        shownUncertainty.note.includes('discovery completeness remains unverified') &&
        shownUncertainty.text.includes('Recorded sources do not establish exhaustive'),
        { shownUncertainty, uncertainty });
      if (scheme === 'dark') {
        const [uncertaintyDownload] = await Promise.all([
          page.waitForEvent('download', { timeout: 10000 }),
          page.click('#uncdownload')
        ]);
        const exportedUncertainties = JSON.parse(fs.readFileSync(await uncertaintyDownload.path(), 'utf8'));
        check('Uncertainty JSON export reproduces the saved-scan API register',
          JSON.stringify(exportedUncertainties) === JSON.stringify(uncertainty),
          { exportedUncertainties, uncertainty });

        const [txtDownload] = await Promise.all([
          page.waitForEvent('download', { timeout: 15000 }),
          page.click('#rawdownload')
        ]);
        const rawText = fs.readFileSync(await txtDownload.path(), 'utf8');
        const rawSection = label => {
          const startTag = '[START_' + label + ']\n';
          const endTag = '\n[END_' + label + ']';
          const start = rawText.indexOf(startTag);
          const end = rawText.indexOf(endTag, start + startTag.length);
          if (start < 0 || end < 0) throw Error('Incomplete raw evidence section: ' + label);
          return JSON.parse(rawText.slice(start + startTag.length, end));
        };
        check('Complete fenced TXT export retains saved evidence, correlations and logs',
          rawText.startsWith(String.fromCharCode(96).repeat(3) + 'text\n') &&
          rawText.includes('COVERAGE: UNKNOWN_BEYOND_RECORDED_SOURCES') &&
          rawText.includes('CONSISTENCY: NON_ATOMIC_ENDPOINT_SNAPSHOT') &&
          JSON.stringify(rawSection('SCAN_METADATA')) === JSON.stringify(row) &&
          JSON.stringify(rawSection('UNCERTAINTY_REGISTER')) === JSON.stringify(uncertainty) &&
          JSON.stringify(rawSection('DATA_ELEMENTS')) === JSON.stringify(elements) &&
          JSON.stringify(rawSection('CORRELATIONS')) === JSON.stringify(correlations) &&
          JSON.stringify(rawSection('RELATIONSHIP_GRAPH')) === JSON.stringify(graph) &&
          JSON.stringify(rawSection('SCAN_LOG')) === JSON.stringify(log),
          { characters: rawText.length, elements: elements.length, correlations: correlations.length });
      }
      await audit(page, `${scheme} summary`);

      // Analysis: Huntsman's offline analysis of the saved entities, every count as the API holds it.
      await page.click('#sctabs a[data-tab=analysis]');
      await page.waitForSelector('#acounts dd', { timeout: 5000 }).catch(() => {});
      const analysed = await api(page, root + '/analyze');
      const counts = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#acounts dt')].map(dt => [dt.textContent, dt.nextElementSibling.textContent])));
      check(`${scheme}: Analysis shows every count the API answers`,
        analysed.counts && Object.keys(analysed.counts).length > 0 && Object.entries(analysed.counts).every(([k, v]) => counts[k] === String(v)) && (await page.textContent('#areport')).length > 0,
        { counts, api: analysed.counts });
      await audit(page, `${scheme} analysis`);

      // Browse: the data types, then one type's elements with the full raw record behind each.
      await page.click('#sctabs a[data-tab=browse]');
      await page.waitForSelector('#types tr a');
      check(`${scheme}: Browse lists every data type`, (await page.$$('#types tr')).length === summary.length, summary.length);
      await audit(page, `${scheme} browse`);
      // Browse the type of an element that shows an entity, within the 200 rows a type lists, so
      // its raw record can also be attributed to its sources below.
      let attributable = null;
      for (const [i, e] of elements.entries()) {
        if (!attributable && e.entity && e.type !== 'ROOT' && elements.slice(0, i).filter(t => t.type === e.type).length < 200) attributable = e;
      }
      check(`${scheme}: the scan holds an element that shows an entity`, attributable !== null, elements.length);
      const want = attributable || elements.find(e => e.type !== 'ROOT') || elements[0];
      await page.click(`#types tr a[href$="/browse/${encodeURIComponent(want.type)}"]`);
      await page.waitForSelector('#bbody tbody tr');
      const type = decodeURIComponent((await page.evaluate(() => location.hash)).split('/')[4] || '');
      const ofType = elements.filter(e => e.type === type);
      check(`${scheme}: Browse shows every element of a type`, (await page.$$('#bbody tbody tr')).length === Math.min(200, ofType.length) && ofType.length > 0, `${type}: ${(await page.$$('#bbody tbody tr')).length} of ${ofType.length}`);
      const wantRow = await page.$$eval('#bbody details.raw summary > .data', (cells, data) => cells.findIndex(c => c.textContent === data), String(want.data));
      await page.click(`#bbody details.raw summary >> nth=${Math.max(0, wantRow)}`);
      await page.waitForSelector('#bbody details.raw[open] .ent-b', { timeout: 3000 }).catch(() => {});
      check(`${scheme}: an element opens to its raw record`, await page.isVisible('#bbody details.raw[open] .ent-b'), 'closed');
      // Source attribution: /reality for the element's entity, each assertion as the API holds it.
      const opened = await page.evaluate(() => { const d = document.querySelector('#bbody details.raw[open]'); return d ? d.closest('tr').querySelector('.data').textContent : null; });
      const attributedPick = elements.find(e => e.type === type && String(e.data) === opened);
      if (attributedPick && attributedPick.entity) {
        await page.click('#bbody details.raw[open] .ent-b button:has-text("Source attribution")');
        await page.waitForSelector('#bbody details.raw[open] .ent-b .ent-b', { timeout: 5000 }).catch(() => {});
        const assessed = await api(page, root + '/reality?uid=' + encodeURIComponent(attributedPick.entity));
        const rows = await page.$$('#bbody details.raw[open] .ent-b .ent-b tbody tr');
        const attributed = await page.textContent('#bbody details.raw[open] .ent-b .ent-b');
        check(`${scheme}: Source attribution lists every assertion the API answers for the entity`,
          assessed.entity && rows.length === assessed.entity.assertions.length && attributed.includes(assessed.entity.identity_status) && assessed.entity.limitations.every(l => attributed.includes(l)),
          { rows: rows.length, assertions: assessed.entity && assessed.entity.assertions.length, attributed });
      } else {
        check(`${scheme}: the opened element names an entity to attribute`, false, { opened, type });
      }
      await audit(page, `${scheme} browse type`);
      await page.click('#bpath');
      await page.waitForSelector('#bbody .tree li', { timeout: 5000 }).catch(() => {});
      const leaves = await page.$$eval('#bbody .tree li.hit > .data', l => new Set(l.map(e => e.textContent)).size);
      check(`${scheme}: Discovery Path places every element of the type`, leaves === new Set(ofType.map(e => String(e.data))).size, `${leaves} of ${new Set(ofType.map(e => String(e.data))).size}`);
      await audit(page, `${scheme} discovery path`);
      await page.click('#bfull');
      await page.check('#bbody tbody tr >> nth=0 >> input[type=checkbox]');
      const [chosen] = await page.evaluate(() => [...fpsel]);
      await page.click('#bsetfp');
      await page.waitForSelector('#bbody .label.warn', { timeout: 5000 }).catch(() => {});
      // As Spiderfoot's resultsetfp: the element and every element found from it, nothing else.
      const all = await api(page, root + '/elements');
      const branch = new Set([chosen]);
      for (let grew = true; grew;) {
        grew = false;
        for (const e of all) if (e.source && branch.has(e.source) && !branch.has(e.id)) { branch.add(e.id); grew = true; }
      }
      const marked = all.filter(e => e.fp).map(e => e.id);
      check(`${scheme}: a false positive flags the element and everything found from it`, marked.length === branch.size && marked.every(id => branch.has(id)) && await page.isVisible('#bbody .label.warn'), `${marked.length} flagged, branch of ${branch.size}`);
      // Once an element is flagged, the saved-entity analysis refuses rather than launder the
      // flagged evidence, and the page shows the server's reason verbatim.
      await page.click('#sctabs a[data-tab=analysis]');
      await page.waitForSelector('#scerror:not([hidden])', { timeout: 5000 }).catch(() => {});
      check(`${scheme}: Analysis shows the server's refusal verbatim once an element is flagged`, (await page.textContent('#scerror')).includes('false-positive elements'), await page.textContent('#scerror'));
      // Chromium logs that refused fetch as a console error; the one 409 is the refusal just read.
      const refusal = errors.findIndex(e => e.includes('status of 409'));
      if (refusal >= 0) errors.splice(refusal, 1);

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
      await page.waitForFunction(DOTS, graph.nodes.length, { timeout: 5000 }).catch(() => {});
      const dots = await page.evaluate(DOTS);
      check(`${scheme}: Graph draws every node`, dots === graph.nodes.length, `${dots} of ${graph.nodes.length}`);
      // Tapping the target's dot, once the layout has settled, says what it is.
      await page.waitForFunction(() => raf === 0, null, { timeout: 25000 }).catch(() => {});
      await page.locator('#gsvg').scrollIntoViewIfNeeded();
      const spot = await page.evaluate(() => { const p = document.querySelector('#gnodes path.groot'), [x, y] = p.getAttribute('d').slice(1).split('h')[0].split(' ').map(Number), m = p.getScreenCTM(); return { x: m.a * x + m.c * y + m.e, y: m.b * x + m.d * y + m.f }; });
      await page.touchscreen.tap(spot.x, spot.y);
      check(`${scheme}: tapping an element in the Graph says what it is`, (await page.textContent('#ginfo')).startsWith('ROOT: ' + TARGET), await page.textContent('#ginfo'));
      // The graph as the page drew it now, after the false positive was flagged above.
      const liveGraph = await api(page, root + '/graph');
      const rootNode = liveGraph.nodes.find(n => n.type === 'ROOT');
      const flaggedNodes = liveGraph.nodes.filter(n => n.fp).length;
      const legend = await page.evaluate(() => [...document.querySelectorAll('#glegend span')].map(s => s.textContent));
      check(`${scheme}: the Graph legend names every data type and counts the false positives`,
        flaggedNodes > 0 && legend.length === new Set(liveGraph.nodes.map(n => n.type)).size + 1 &&
        legend.includes(flaggedNodes + ' flagged false positive') &&
        rootNode && rootNode.module && (await page.textContent('#ginfo')).includes(' · ' + rootNode.module),
        { legend, types: new Set(liveGraph.nodes.map(n => n.type)).size, flaggedNodes, ginfo: await page.textContent('#ginfo') });
      await audit(page, `${scheme} graph`);
      // Save image keeps every element and how each is drawn, without the page's styles.
      const [image] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#gsave')]);
      const svgText = fs.readFileSync(await image.path(), 'utf8');
      check(`${scheme}: Save image keeps every element as a dot`, image.suggestedFilename().endsWith('.svg') && (svgText.match(/h0/g) || []).length >= graph.nodes.length && svgText.includes('stroke-linecap="round"') && !svgText.includes('class='), image.suggestedFilename());
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
      const wild = '*' + probe.slice(1, -1) + '*';
      await page.fill('#scq', wild);
      await page.click('#scsearch button');
      await page.waitForSelector('#pane-search:not([hidden])');
      // The server's matcher decides, so the page shows exactly what the API finds in this scan.
      const sought = await api(page, '/api/scans/search?' + new URLSearchParams({ value: wild, ids: root.split('/').pop() }));
      const soughtRows = (await page.$$('#sresults tbody tr:not(:has(td.none))')).length;
      check(`${scheme}: a wildcard search finds the element`, sought.some(x => String(x.data) === probe) && soughtRows === Math.min(200, sought.length), `${probe}: ${soughtRows} rows, API ${sought.length}`);
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
      await page.fill('#seeds', '0.0,179.99\n0.0,-179.99');
      await page.click('#arun');
      await page.waitForSelector('#aresult:not([hidden])', { timeout: 20000 });
      const geoTable = await page.textContent('#ageo');
      check(`${scheme}: GEOINT shows the short antimeridian distance from two seeds`,
        (await page.$$('#ageo tr')).length === 1 && geoTable.includes('2223') &&
        !await page.textContent('#ageonote'), geoTable);


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
      // A key saved from Settings lands in the keys file every lookup reads, at mode 600, sent in
      // the request body; no answer and nothing on the page carries it back. Shodan's slot, which
      // no phone lookup uses, and it is removed again before any scan runs.
      if (scheme === 'light') {
        const KEY = 'TEST_ONLY_WEB_UI_KEY_3e9a';
        const sent = [], answers = [];
        const ask = r => sent.push(r.url() + ' ' + (r.postData() || ''));
        const answered = r => { if (r.url().includes('/api/')) answers.push(r.text().catch(() => '')); };
        page.on('request', ask);
        page.on('response', answered);
        const file = path.join(home, '.huntsman.env');
        const cellState = () => page.evaluate(() => {
          const td = document.querySelector('#mods tr').cells[3];
          return { label: td.querySelector('.label').textContent, note: (td.querySelector('[role=status]') || {}).textContent || '', typed: [...td.querySelectorAll('input')].map(i => i.value).join('') };
        });
        await page.fill('#mfilter', 'shodan host');
        check('Settings filters to the module that reads a slot', (await page.$$('#mods tr')).length === 1, (await page.$$('#mods tr')).length);
        await page.click('#mods tr .keyedit summary');
        await page.fill('#mods tr input[data-slot=HUNTSMAN_SHODAN_KEY]', KEY);
        await page.click('#mods tr .keyedit button[type=submit]');
        await page.waitForFunction(() => /saved to/.test((document.querySelector('#mods [role=status]') || {}).textContent || ''), null, { timeout: 5000 }).catch(() => {});
        const saved = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
        const mode = fs.existsSync(file) ? (fs.statSync(file).mode & 0o777).toString(8) : 'none';
        check('Settings saves a key into the keys file at mode 600', saved === `HUNTSMAN_SHODAN_KEY='${KEY}'\n` && mode === '600', { saved: saved.replace(KEY, '<key>'), mode });
        const after = await cellState();
        check('a saved key reads as set and its field is empty again', after.label === 'set' && /saved to/.test(after.note) && after.typed === '', after);
        await audit(page, 'settings key editor');
        await page.click('#mods tr .keyedit button.btn-ghost');
        await page.waitForFunction(() => /removed from/.test((document.querySelector('#mods [role=status]') || {}).textContent || ''), null, { timeout: 5000 }).catch(() => {});
        const removed = await cellState();
        const left = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
        check('Remove takes the key out of the keys file', removed.label === 'not set' && !left.includes('HUNTSMAN_SHODAN_KEY'), { removed, left: left.replace(KEY, '<key>') });
        // Spiderfoot's Import API Keys: its SpiderFoot.cfg export, pasted or chosen as a file, fills
        // the slots its keys belong to and names the keys no Huntsman source takes.
        const PASTED = 'TEST_ONLY_WEB_UI_IMPORT_8b2f', CHOSEN = 'TEST_ONLY_WEB_UI_FILE_4d7a';
        const imported = () => page.waitForFunction(() => {
          const note = document.getElementById('kimp-m').textContent;
          const row = [...document.querySelectorAll('#mods tr')].find(tr => tr.cells[0]?.textContent.trim().toLowerCase() === 'shodan');
          const label = row?.cells[3].querySelector('.label')?.textContent;
          return /^Imported/.test(note) && label === 'set';
        }, null, { timeout: 5000 }).catch(() => {});
        await page.click('#kimp summary');
        await page.fill('#kimp-text', `sfp_fullhunt:api_key=TEST_ONLY_UNUSED\nsfp_shodan:api_key=${PASTED}\nsfp_spider:maxpages=100\n`);
        await page.click('#kimp button[type=submit]');
        await imported();
        const note = await page.evaluate(() => {
          const row = [...document.querySelectorAll('#mods tr')].find(tr => tr.cells[0]?.textContent.trim().toLowerCase() === 'shodan');
          return { note: document.getElementById('kimp-m').textContent, typed: document.getElementById('kimp-text').value, label: row?.cells[3].querySelector('.label')?.textContent || 'missing shodan row' };
        });
        const pasted = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
        check('Import API keys saves a pasted Spiderfoot export into the keys file', pasted === `HUNTSMAN_SHODAN_KEY='${PASTED}'\n` && note.label === 'set' && note.typed === '', { pasted: pasted.replace(PASTED, '<key>'), note });
        check('the import names the keys no Huntsman source takes', note.note.includes('HUNTSMAN_SHODAN_KEY') && note.note.includes('sfp_fullhunt:api_key') && /1 Spiderfoot setting/.test(note.note), note.note);
        await audit(page, 'settings key import');
        await page.evaluate(() => { document.getElementById('kimp-m').textContent = ''; });
        await page.setInputFiles('#kimp-file', { name: 'SpiderFoot.cfg', mimeType: 'text/plain', buffer: Buffer.from(`sfp_virustotal:api_key=${CHOSEN}\n`) });
        await page.click('#kimp button[type=submit]');
        await imported();
        const chosen = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
        check('Import API keys reads a chosen SpiderFoot.cfg', chosen === `HUNTSMAN_SHODAN_KEY='${PASTED}'\nHUNTSMAN_VIRUSTOTAL_KEY='${CHOSEN}'\n` && (fs.statSync(file).mode & 0o777) === 0o600, chosen.replace(PASTED, '<key>').replace(CHOSEN, '<key>'));
        // No scan in this check may run with a key.
        fs.unlinkSync(file);
        page.off('request', ask);
        page.off('response', answered);
        const bodies = await Promise.all(answers);
        check('the key travels only in a request body', sent.some(r => r.includes('/api/settings/keys ') && r.includes(KEY)) && !sent.some(r => r.split(' ')[0].includes(KEY)), sent.length);
        const content = await page.content();
        check('no answer and nothing on the page carries a key back', [KEY, PASTED, CHOSEN].every(k => !bodies.some(b => b.includes(k)) && !content.includes(k)), bodies.filter(b => [KEY, PASTED, CHOSEN].some(k => b.includes(k))).length);
        check('an imported key travels only in a request body', sent.some(r => r.includes(PASTED)) && sent.some(r => r.includes(CHOSEN)) && !sent.some(r => [PASTED, CHOSEN].some(k => r.split(' ')[0].includes(k))), sent.length);
        await page.fill('#mfilter', '');
      }
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
        // A value the scan found that is itself a target opens New Scan on it.
        const found = elements.find(e => e.type === 'PHONE_NUMBER');
        await page.goto(base + '/#/scan/' + encodeURIComponent(id) + '/browse/PHONE_NUMBER', { waitUntil: 'networkidle' });
        await page.waitForSelector('#bbody details.raw summary', { timeout: 5000 }).catch(() => {});
        await page.click('#bbody details.raw summary >> nth=0');
        await page.waitForSelector('#bbody details.raw[open] .pivot', { timeout: 3000 }).catch(() => {});
        await audit(page, 'dark element with New Scan of this');
        await page.click('#bbody details.raw[open] .pivot');
        await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 }).catch(() => {});
        const pivoted = await page.evaluate(() => ({ target: document.getElementById('starget').value, kind: document.getElementById('skind').value, depth: document.getElementById('sdepth').value }));
        check('an element opens New Scan on its value', !!found && pivoted.target === String(found.data) && pivoted.kind === 'auto' && pivoted.depth === '1', { found: found && found.data, pivoted });
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
        const shownCompare = await page.evaluate(() => ({ hash: location.hash, meta: document.getElementById('cmpmeta').textContent, coverage: document.getElementById('cmpcoverage').textContent, types: document.querySelectorAll('#cmptypes tr').length, added: document.getElementById('cmpadd-n').textContent, removed: document.getElementById('cmprem-n').textContent }));
        check('Compare opens on the earlier scan of the same target', shownCompare.hash === '#/compare/' + pair, shownCompare.hash);
        check('Compare shows what the API compares', shownCompare.types === Math.max(1, compared.types.length) && shownCompare.added === String(compared.added.length) && shownCompare.removed === String(compared.removed.length) && shownCompare.meta.includes('No change') === compared.unchanged, { shownCompare, types: compared.types.length, added: compared.added.length, removed: compared.removed.length, unchanged: compared.unchanged });
        check('Compare displays both source-execution summaries',
          compared.source_execution && shownCompare.coverage.includes('Earlier: ' + compared.source_execution.earlier.accepted + ' of ' + compared.source_execution.earlier.total) &&
          shownCompare.coverage.includes('Later: ' + compared.source_execution.later.accepted + ' of ' + compared.source_execution.later.total) &&
          compared.source_execution_changed === false, shownCompare.coverage);
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
        // Search every scan, which Spiderfoot's page cannot: each hit names its scan, as the API answers.
        await page.goto(base + '/#/scans', { waitUntil: 'networkidle' });
        await page.waitForSelector('#scans tr');
        await page.fill('#allq', TARGET);
        await page.click('#allsearch button');
        await page.waitForSelector('#allresults tbody tr', { timeout: 5000 }).catch(() => {});
        const everywhere = await api(page, '/api/scans/search?value=' + encodeURIComponent(TARGET));
        const hitRows = (await page.$$('#allresults tbody tr:not(:has(td.none))')).length;
        const hitScans = await page.$$eval('#allresults td[data-label=Scan] a', l => [...new Set(l.map(a => decodeURIComponent(a.getAttribute('href').split('/')[2])))]);
        check('Search finds a value in every scan, each hit naming its scan', everywhere.length > 0 && hitRows === Math.min(200, everywhere.length) && hitScans.length === new Set(everywhere.map(x => x.scan_id)).size && hitScans.includes(id) && hitScans.includes(again), { hitRows, api: everywhere.length, hitScans });
        await audit(page, 'dark search every scan');
        await page.goto(base + '/#/scan/' + encodeURIComponent(again) + '/summary', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => document.getElementById('scstatus').textContent === 'FINISHED', null, { timeout: 5000 }).catch(() => {});
        await page.click('#scdelete');
        await page.waitForFunction(() => location.hash === '#/scans', null, { timeout: 10000 }).catch(() => {});
        const left = await api(page, '/api/scans');
        check('Delete removes the scan', !left.some(s => s.id === again) && left.some(s => s.id === id), left.map(s => s.id));

        // By Module: only the ticked modules are asked. Nothing ticked, or only modules the
        // target's lookup does not ask, is refused before a scan is saved.
        const phone = asked.filter(m => m.lookups.includes('phone')).map(m => m.name);
        const one = phone.includes('numverify') ? 'numverify' : phone[0];
        const elsewhere = asked.find(m => m.lookups.length && !m.lookups.includes('phone'));
        const box = name => `#modlist input[value="${name}"]`;
        await page.goto(base + '/#/newscan', { waitUntil: 'networkidle' });
        await page.click('#nt-modules');
        await page.waitForSelector('#modlist input');
        await page.fill('#starget', TARGET);
        await page.fill('#sname', 'check by module');
        await page.fill('#sdepth', '0');
        await page.click('#nnone');
        check('De-Select All clears every module', (await page.$$('#modlist input:checked')).length === 0, (await page.$$('#modlist input:checked')).length);
        await page.click('#runscan');
        check('a by-module scan with no module ticked is refused on the page', (await page.textContent('#nerror')) === 'Select at least one module.', await page.textContent('#nerror'));
        const before = (await api(page, '/api/scans')).length;
        await page.check(box(elsewhere.name));
        const quiet = errors.length;
        await page.click('#runscan');
        await page.waitForFunction(() => /none of the chosen modules/.test(document.getElementById('nerror').textContent), null, { timeout: 5000 }).catch(() => {});
        // The browser logs the refused request; that 400 is the one console error expected here.
        const refusal = errors.splice(quiet);
        check('the refused by-module scan logs nothing but its 400', refusal.every(e => e.includes('status of 400')), refusal);
        check('a by-module scan whose modules do not look up the target shows why and saves nothing', (await page.textContent('#nerror')).includes(`none of the chosen modules (${elsewhere.name})`) && (await api(page, '/api/scans')).length === before, { error: await page.textContent('#nerror'), module: elsewhere.name });
        await audit(page, 'dark new scan by module refused');
        await page.uncheck(box(elsewhere.name));
        await page.check(box(one));
        await page.click('#runscan');
        await page.waitForFunction(() => /^#\/scan\/[^/]+/.test(location.hash) && !document.getElementById('view-scan').hidden, null, { timeout: 10000 }).catch(() => {});
        const picked = decodeURIComponent((await page.evaluate(() => location.hash)).split('/')[2] || '');
        await page.waitForFunction(() => ['FINISHED', 'ABORTED', 'ERROR-FAILED'].includes(document.getElementById('scstatus').textContent), null, { timeout: 90000 }).catch(() => {});
        const byModule = await api(page, '/api/scans/' + encodeURIComponent(picked));
        check('a by-module scan asks only the ticked module', byModule.status === 'FINISHED' && JSON.stringify(byModule.options.modules) === JSON.stringify([one]) && byModule.honoured.modules === true && !(byModule.modules_run || []).some(m => m !== one && phone.includes(m)), { status: byModule.status, modules: byModule.options && byModule.options.modules, honoured: byModule.honoured, run: byModule.modules_run });
        await page.click('#sctabs a[data-tab=settings]');
        await page.waitForFunction(() => /Modules applied/.test(document.getElementById('opts').textContent), null, { timeout: 5000 }).catch(() => {});
        const opts = await page.textContent('#opts');
        check('the scan\'s Settings show the chosen module, applied', opts.includes(one) && !opts.includes('not applied yet: every module'), opts.slice(0, 300));
        await page.click('#scclone');
        await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 }).catch(() => {});
        await page.waitForSelector('#modlist input', { timeout: 5000 }).catch(() => {});
        const recloned = await page.evaluate(() => ({ tab: document.getElementById('nt-modules').getAttribute('aria-selected'), shown: !document.getElementById('np-modules').hidden, ticked: [...document.querySelectorAll('#modlist input:checked')].map(i => i.value) }));
        check('Clone of a by-module scan ticks its modules', recloned.tab === 'true' && recloned.shown && JSON.stringify(recloned.ticked) === JSON.stringify([one]), recloned);
        await audit(page, 'dark cloned by-module scan');
        // A scan that chose a module by its Spiderfoot name, in any case, clones to that module.
        const sfName = asked.find(m => m.name === one).spiderfoot.find(n => n.startsWith('sfp_'));
        const started = await page.request.post(base + '/api/scans?' + new URLSearchParams({ target: TARGET, name: 'check Spiderfoot name', modules: sfName.toUpperCase() }), { headers: LH });
        const sfScan = await started.json();
        await page.goto(base + '/#/scan/' + encodeURIComponent(sfScan.id) + '/summary', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => ['FINISHED', 'ABORTED', 'ERROR-FAILED'].includes(document.getElementById('scstatus').textContent), null, { timeout: 90000 }).catch(() => {});
        await page.click('#scclone');
        await page.waitForSelector('#view-newscan:not([hidden])', { timeout: 5000 }).catch(() => {});
        const sfTicked = await page.$$eval('#modlist input:checked', l => l.map(i => i.value));
        check('Clone of a scan that chose a Spiderfoot module name ticks the module doing its work', started.status() === 202 && JSON.stringify(sfTicked) === JSON.stringify([one]), { status: started.status(), sfName, sfTicked });
        await page.click('#nt-usecase');
      }
      check(`${scheme}: no console errors`, errors.length === 0, errors);
      kept = (await api(page, '/api/scans')).length;
      await ctx.close();
    }

    // A big scan, as a crawl of a large domain leaves one, on a phone's CPU: its Graph draws every
    // node and keeps the page answering while it arranges them, and leaving the Graph stops the
    // arranging and lets its nodes go. The scan is written into the store from one the check ran.
    {
      const store = path.join(home, '.huntsman', 'scans');
      const from = path.join(store, fs.readdirSync(store)[0]);
      const id = 'b16b16b16b16b16b', dir = path.join(store, id), BIG = 3000;
      const row = JSON.parse(fs.readFileSync(path.join(from, 'scan.json'), 'utf8'));
      const results = JSON.parse(fs.readFileSync(path.join(from, 'results.json'), 'utf8'));
      const root = results.elements.find(e => !e.source);
      const eid = i => 'c' + i.toString(16).padStart(15, '0');
      const kinds = ['INTERNET_NAME', 'IP_ADDRESS', 'EMAILADDR', 'LINKED_URL_INTERNAL', 'RAW_RIR_DATA', 'DOMAIN_NAME', 'IPV6_ADDRESS',
        'RAW_DNS_RECORDS', 'PROVIDER_DNS', 'NETBLOCK_OWNER', 'BGP_AS_OWNER', 'SSL_CERTIFICATE_ISSUED', 'DOMAIN_WHOIS', 'DOMAIN_REGISTRAR',
        'WEBSERVER_BANNER', 'TCP_PORT_OPEN', 'COUNTRY_NAME', 'GEOINFO', 'PROVIDER_HOSTING', 'CO_HOSTED_SITE', 'LINKED_URL_EXTERNAL',
        'HTTP_CODE', 'SOFTWARE_USED', 'PHONE_NUMBER', 'USERNAME'];
      results.scan_id = id;
      results.elements = [root, ...Array.from({ length: BIG }, (_, i) => ({ id: eid(i), type: kinds[i % kinds.length], data: `host-${i}.example.com`, source: i < 3 ? root.id : eid(Math.floor(i / 3) - 1), module: 'check', confidence: 90, created: row.created + i, fp: false }))];
      Object.assign(row, { id, name: 'big graph', elements: BIG + 1, unique: BIG + 1 });
      fs.mkdirSync(dir, { mode: 0o700 });
      fs.writeFileSync(path.join(dir, 'scan.json'), JSON.stringify(row), { mode: 0o600 });
      fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(results), { mode: 0o600 });
      fs.copyFileSync(path.join(from, 'log.jsonl'), path.join(dir, 'log.jsonl'));
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      const errors = [];
      page.on('pageerror', e => errors.push(String(e)));
      await (await ctx.newCDPSession(page)).send('Emulation.setCPUThrottlingRate', { rate: 4 });
      const frames = ms => page.evaluate(ms => new Promise(done => { let n = 0; const t0 = performance.now(); requestAnimationFrame(function tick() { n++; if (performance.now() - t0 < ms) requestAnimationFrame(tick); else done(n); }); }), ms);
      await page.goto(base + '/#/scan/' + id + '/graph', { waitUntil: 'networkidle' });
      await page.waitForFunction(DOTS, BIG + 1, { timeout: 30000 }).catch(() => {});
      const drawn = await page.evaluate(DOTS);
      const arranging = await frames(2000);
      const t = Date.now();
      await page.click('#sctabs a[data-tab=log]');
      await page.waitForSelector('#log tr', { timeout: 30000 }).catch(() => {});
      const logMs = Date.now() - t;
      const after = await frames(1000), remaining = await page.evaluate(() => document.querySelectorAll('#gnodes path').length);
      metrics.bigGraph = { nodes: BIG + 1, drawn, framesIn2s: arranging, logMs, framesIn1sAfter: after, nodesLeft: remaining };
      check('a big scan\'s Graph draws every node', drawn === BIG + 1, `${drawn} of ${BIG + 1}`);
      const bigLegend = await page.evaluate(() => document.querySelectorAll('#glegend span').length);
      check('a big scan\'s Graph legend names every one of its data types', bigLegend === kinds.length + 1, `${bigLegend} of ${kinds.length + 1}`);
      check('a big scan\'s Graph keeps the page answering while it arranges', arranging >= 30, `${arranging} frames in 2 s at 4x CPU throttling`);
      check('leaving a big scan\'s Graph stops its arranging and lets its nodes go', logMs < 3000 && after >= 30 && remaining === 0, metrics.bigGraph);
      check('no console errors on a big scan', errors.length === 0, errors);
      await ctx.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }

    // A stopped server is named, with the command that starts it; its return is noticed without
    // a reload, and the saved scans are all still there. A scan the stopped server left RUNNING,
    // as Android leaves one when it kills the server mid-scan, reads ABORTED after the restart
    // and offers Delete, instead of a RUNNING row nobody can act on.
    {
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      await page.waitForSelector('#scans tr');
      await stop();
      const store = path.join(home, '.huntsman', 'scans');
      const from = path.join(store, fs.readdirSync(store).find(name => /^[0-9a-f]{16}$/.test(name)));
      const orphan = 'ab0ab0ab0ab0ab0a', orphanDir = path.join(store, orphan);
      const row = JSON.parse(fs.readFileSync(path.join(from, 'scan.json'), 'utf8'));
      Object.assign(row, { id: orphan, name: 'left running', status: 'RUNNING', ended: null });
      delete row.owner;
      delete row.owner_started;
      fs.mkdirSync(orphanDir, { mode: 0o700 });
      fs.writeFileSync(path.join(orphanDir, 'scan.json'), JSON.stringify(row), { mode: 0o600 });
      await page.click('#srefresh');
      await page.waitForSelector('#serror:not([hidden])', { timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(300);
      const down = { error: await page.textContent('#serror'), pill: await page.textContent('#state') };
      metrics.serverDown = down;
      check('a stopped server is named with the command that starts it', /huntsman start/.test(down.error) && down.pill === 'offline', down);
      await serve(new URL(base).host);
      await page.waitForFunction(() => document.getElementById('state').textContent === 'online', null, { timeout: 9000 }).catch(() => {});
      check('the page notices the server is back', (await page.textContent('#state')) === 'online', await page.textContent('#state'));
      check('a server started again on the same build does not ask to reload', await page.isHidden('#upgraded'), 'shown');
      await page.click('#srefresh');
      await page.waitForFunction(() => document.getElementById('serror').hidden, null, { timeout: 5000 }).catch(() => {});
      check('saved scans survive a server restart', (await page.$$('#scans tr')).length === kept + 1 && kept > 0, `${(await page.$$('#scans tr')).length} of ${kept + 1}`);
      const left = (await api(page, '/api/scans')).find(s => s.id === orphan);
      const shown = await page.$$eval('#scans tr', trs => trs.filter(tr => tr.textContent.includes('left running')).map(tr => ({
        status: (tr.querySelector('td[data-label=Status]') || {}).textContent,
        actions: [...tr.querySelectorAll('td[data-label=Action] button')].map(b => b.textContent),
      })));
      metrics.leftRunning = { left, shown };
      check('a scan the stopped server left running reads ABORTED after the restart and offers Delete',
        !!left && left.status === 'ABORTED' && left.ended > 0 && shown.length === 1 && shown[0].status === 'ABORTED' && shown[0].actions.includes('Delete') && !shown[0].actions.includes('Stop'),
        { left, shown });
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
