#!/usr/bin/env node
// The serve web UI in a phone's browser, checked end to end. It starts `huntsman-recon serve` on a
// free loopback port, drives the page at 360x740 with touch in both system themes, and fails when
// a behaviour the page promises does not hold: it loads with no console error or policy
// violation, fits the screen, passes axe-core's WCAG 2.2 AA rules in both themes, shows a lookup's
// findings with their evidence, keeps the last lookup and analysis across a reload, asks only for
// health when the tab comes back, lets a slow lookup be stopped, says what to do when the server
// stops and notices when it is back, and saves the report it shows.
//
// It never spends a key: the server runs with a scratch HOME and none of the caller's
// HUNTSMAN_*, HSE_* or *_KEY variables, and the one lookup it runs (a phone number) is offline.
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
const PAGE_BUDGET = 40 * 1024;
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
const SEEDS = ['alice@example.com', 'example.com', '@alice', '+61412345678', 'Alice Smith', '203.0.113.7'].join('\n');

(async () => {
  const base = await serve('127.0.0.1:0');
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || process.env.CHROME_BIN || undefined });
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
        const controls = [...document.querySelectorAll('button,input,select,textarea,a,summary')].filter(e => e.getBoundingClientRect().width > 0);
        return {
          htmlBytes: n.decodedBodySize, dclMs: Math.round(n.domContentLoadedEventEnd), fcpMs: f ? Math.round(f.startTime) : null,
          overflowPx: document.documentElement.scrollWidth - window.innerWidth,
          smallTargets: controls.filter(e => { const r = e.getBoundingClientRect(); return r.height < 44 || r.width < 44; }).map(e => e.id || e.tagName),
          csp: window.__csp || [], pill: document.getElementById('state').textContent,
        };
      });
      metrics.cold = { ...m, requests: [...paths] };
      check('console errors on load', errors.length === 0, errors);
      check('policy violations on load', m.csp.length === 0, m.csp);
      check('page fits 360 px', m.overflowPx <= 0, `${m.overflowPx} px of horizontal overflow`);
      check('tap targets of 44 px', m.smallTargets.length === 0, m.smallTargets);
      check('page weight', m.htmlBytes <= PAGE_BUDGET, `${m.htmlBytes} bytes, budget ${PAGE_BUDGET}`);
      check('cold load asks only for the page, health and icon', paths.every(p => ['/', '/api/health', '/favicon.svg'].includes(p)), paths);
      check('server shown online', m.pill === 'online', m.pill);

      // A tab that comes back into view asks for health and nothing else. The browser's own
      // late icon fetch is not the page's.
      const again = [];
      page.on('request', r => { const p = new URL(r.url()).pathname; if (p.startsWith('/api/')) again.push(p); });
      for (let i = 0; i < 3; i++) {
        await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange')); });
        await page.waitForTimeout(200);
      }
      metrics.tabReturns = { returns: 3, requests: [...again] };
      check('a returning tab asks only for health', again.length === 3 && again.every(p => p === '/api/health'), again);

      // Status loads the module list and the command contract once.
      again.length = 0;
      await page.goto(base + '/#/status', { waitUntil: 'networkidle' });
      await page.waitForFunction(() => ['modules', 'command'].every(id => document.getElementById(id).textContent !== '…'), null, { timeout: 5000 }).catch(() => {});
      await page.goto(base + '/#/lookup', { waitUntil: 'networkidle' });
      await page.goto(base + '/#/status', { waitUntil: 'networkidle' });
      check('status loads its details once', again.filter(p => p === '/api/modules').length === 1 && again.filter(p => p === '/api/command').length === 1, again);
      check('status shows the module count', /^\d+$/.test(await page.textContent('#smodules')), await page.textContent('#smodules'));
      await ctx.close();
    }

    // Both system themes: colours, the browser bar, contrast in every view, the flows.
    for (const scheme of ['dark', 'light']) {
      const ctx = await browser.newContext({ ...PHONE, colorScheme: scheme });
      const page = await ctx.newPage();
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      const look = () => page.evaluate(() => ({ bg: getComputedStyle(document.body).backgroundColor, bar: document.querySelector('meta[name=theme-color]').content }));
      const first = await look();
      const lightBg = 'rgb(238, 241, 244)', darkBg = 'rgb(10, 13, 17)';
      check(`${scheme}: page follows the system theme`, first.bg === (scheme === 'light' ? lightBg : darkBg), first);
      check(`${scheme}: browser bar matches the app bar`, first.bar === (scheme === 'light' ? '#ffffff' : '#11151b'), first);
      await axe(page, `${scheme} lookup`);

      // Analysis through the form.
      await page.goto(base + '/#/analyze', { waitUntil: 'networkidle' });
      await page.fill('#seeds', SEEDS);
      let t = Date.now();
      await page.click('#arun');
      await page.waitForSelector('#aresult:not([hidden])', { timeout: 20000 });
      metrics[`${scheme}AnalyzeMs`] = Date.now() - t;
      check(`${scheme}: analysis lists entities`, (await page.$$('#aentities tr')).length >= 6, 'too few rows');
      await axe(page, `${scheme} analysis`);

      // A lookup through the form: every entity, its evidence and attributes, every source with why.
      await page.goto(base + '/#/lookup', { waitUntil: 'networkidle' });
      await page.selectOption('#kind', 'phone');
      await page.fill('#q', '+61412345678');
      t = Date.now();
      await page.click('#run');
      await page.waitForSelector('#result:not([hidden]), #lerror:not([hidden])', { timeout: 60000 });
      metrics[`${scheme}LookupMs`] = Date.now() - t;
      const api = await (await page.request.get(base + '/api/lookup?kind=phone&q=%2B61412345678', { headers: { 'X-Huntsman-Lookup': '1' } })).json();
      const shown = await page.evaluate(() => ({
        error: document.getElementById('lerror').hidden ? null : document.getElementById('lerror').textContent,
        entities: document.querySelectorAll('#findings .ent').length, evidence: document.querySelectorAll('#findings .ev').length,
        attributes: document.querySelectorAll('#findings dd').length, outcomes: document.querySelectorAll('#outcomes tr').length,
        detailColumn: [...document.querySelectorAll('#outcomes')].some(tb => [...tb.parentNode.querySelectorAll('th')].some(th => th.textContent === 'detail')),
        summary: document.getElementById('lwhen')?.textContent ?? null,
      }));
      const evidence = api.entities.reduce((n, e) => n + e.evidence.length, 0);
      check(`${scheme}: lookup answered`, shown.error === null, shown.error);
      check(`${scheme}: every entity is listed`, shown.entities === api.entities.length && shown.entities > 0, shown);
      check(`${scheme}: evidence and attributes are shown`, shown.evidence === evidence && shown.attributes > 0, shown);
      check(`${scheme}: every source is listed with a detail column`, shown.outcomes === api.outcomes.length && shown.detailColumn, shown);
      await axe(page, `${scheme} lookup result`);

      // The report as shown can be saved.
      const [download] = await Promise.all([page.waitForEvent('download', { timeout: 5000 }), page.click('#download')]);
      const saved = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
      check(`${scheme}: Download JSON saves the report`, saved.route === 'phone' && saved.entities.length === api.entities.length, download.suggestedFilename());

      // The toggle overrides the system theme and is remembered.
      await page.click('#theme');
      const flipped = await look();
      check(`${scheme}: toggle flips the theme`, flipped.bg === (scheme === 'light' ? darkBg : lightBg) && flipped.bar === (scheme === 'light' ? '#11151b' : '#ffffff'), flipped);
      await axe(page, `${scheme} toggled`);

      // A reload (Android discarding the tab) brings back the last lookup and analysis, and the theme.
      await page.reload({ waitUntil: 'networkidle' });
      check(`${scheme}: toggled theme survives a reload`, (await look()).bg === flipped.bg, await look());
      check(`${scheme}: lookup survives a reload`, await page.evaluate(() => !document.getElementById('result').hidden && document.querySelectorAll('#findings .ent').length > 0), 'result hidden');
      await page.goto(base + '/#/analyze', { waitUntil: 'networkidle' });
      check(`${scheme}: analysis survives a reload`, await page.evaluate(() => !document.getElementById('aresult').hidden), 'analysis hidden');
      await page.goto(base + '/#/status', { waitUntil: 'networkidle' });
      await axe(page, `${scheme} status`);
      await ctx.close();
    }

    // A slow lookup can be stopped; a stopped server is named, with the command that starts it,
    // and its return is noticed without a reload.
    {
      const ctx = await browser.newContext(PHONE);
      const page = await ctx.newPage();
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      await page.route('**/api/lookup*', route => setTimeout(() => route.continue().catch(() => {}), 5000));
      await page.fill('#q', '+61412345678');
      await page.click('#run');
      await page.waitForTimeout(2200);
      const during = await page.textContent('#run');
      check('a running lookup shows its time and can be stopped', /^Cancel · [12]s$/.test(during), during);
      await page.click('#run');
      await page.waitForSelector('#lerror:not([hidden])', { timeout: 3000 });
      check('stopping says the server finishes the lookup', /^Stopped waiting after/.test(await page.textContent('#lerror')), await page.textContent('#lerror'));
      check('the button is ready again', (await page.textContent('#run')) === 'Look up', await page.textContent('#run'));
      await page.unroute('**/api/lookup*');

      await stop();
      await page.click('#run');
      await page.waitForSelector('#lerror:not([hidden])', { timeout: 5000 });
      await page.waitForTimeout(300);
      const down = { error: await page.textContent('#lerror'), pill: await page.textContent('#state') };
      metrics.serverDown = down;
      check('a stopped server is named with the command that starts it', /huntsman start/.test(down.error) && down.pill === 'offline', down);
      await serve(new URL(base).host);
      await page.waitForFunction(() => document.getElementById('state').textContent === 'online', null, { timeout: 9000 }).catch(() => {});
      check('the page notices the server is back', (await page.textContent('#state')) === 'online', await page.textContent('#state'));
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
