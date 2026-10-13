#!/usr/bin/env node
// Optional operator helper: fetch pages that need a real browser (JavaScript
// challenge pages) and print one JSON object per URL: {url, status, title, text, error}.
//
// This is NOT part of huntsman-recon. The engine is one static ureq binary with no
// browser and no JavaScript, built for Termux aarch64 no-root; a ~400 MB headless
// Chromium cannot ship inside it. This script is for operator-side enrichment on a
// workstation only. It defeats JavaScript challenge pages, but not IP-reputation
// blocks or captchas. Output is designed to pipe into `huntsman-recon investigate`.
//
// Requires Node 18+, the `playwright` package, and a Chromium it can launch
// (Playwright resolves its own under PLAYWRIGHT_BROWSERS_PATH). It never reads
// credentials and makes only the requests named on the command line.
//
// Usage:  node fetch.cjs <url> [url...]
// Env:    HEADLESS_FETCH_WAIT_MS  settle time after load (default 5000)
//         HEADLESS_FETCH_UA       User-Agent override

let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (_) {
  process.stderr.write(
    'headless-fetch: the "playwright" package is not installed. Run `npm install playwright` ' +
      'and ensure a Chromium is available. This helper is optional and not required by huntsman-recon.\n',
  );
  process.exit(2);
}

const urls = process.argv.slice(2);
if (urls.length === 0) {
  process.stderr.write('usage: node fetch.cjs <url> [url...]\n');
  process.exit(64);
}

const WAIT_MS = Number(process.env.HEADLESS_FETCH_WAIT_MS || 5000);
const UA =
  process.env.HEADLESS_FETCH_UA ||
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36';

(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (e) {
    process.stderr.write(`headless-fetch: could not launch Chromium: ${String(e).slice(0, 200)}\n`);
    process.exit(3);
  }
  const ctx = await browser.newContext({ userAgent: UA, locale: 'en-AU' });
  let failures = 0;
  for (const url of urls) {
    const record = { url, status: 0, title: '', text: '', error: null };
    try {
      const page = await ctx.newPage();
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(WAIT_MS);
      record.status = resp ? resp.status() : 0;
      record.title = await page.title().catch(() => '');
      record.text = (await page.evaluate(() => (document.body ? document.body.innerText : ''))).slice(0, 20000);
      await page.close();
    } catch (e) {
      record.error = String(e).slice(0, 300);
      failures += 1;
    }
    process.stdout.write(`${JSON.stringify(record)}\n`);
  }
  await browser.close();
  process.exit(failures === urls.length ? 1 : 0);
})();
