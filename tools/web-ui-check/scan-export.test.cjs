const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

// Run the candidate's exact exporter, route-change logic and API wrapper.
// Synthetic responses and a minimal DOM make request timing deterministic.
const html = fs.readFileSync(path.join(__dirname, '../../src/web_ui.html'), 'utf8');
const scanA = 'a000000000000001';
const scanB = 'b000000000000002';
const sections = [
  ['elements', 'DATA_ELEMENTS'],
  ['correlations', 'CORRELATIONS'],
  ['graph', 'RELATIONSHIP_GRAPH'],
  ['log', 'SCAN_LOG'],
];
function source(first, next) {
  const start = html.indexOf(first);
  const end = html.indexOf(next, start);
  assert.ok(start >= 0 && end > start, 'candidate source boundaries are missing');
  return html.slice(start, end);
}
const exporter = [
  source("const LH=", 'function el('),
  source("const TABS=", 'async function loadScan('),
  source("$('rawdownload').onclick=", 'const sourceOutcomeState='),
].join('\n');

async function runExport({ navigateDuring, rejectEndpoint }) {
  const downloads = [];
  const failures = [];
  const requested = [];
  const dom = new Map();
  const paused = Promise.withResolvers();
  const resume = Promise.withResolvers();

  const context = vm.createContext({
    Blob,
    fixture: { id: scanA, status: 'FINISHED' },
    $: id => {
      if (!dom.has(id)) dom.set(id, { children: [] });
      return dom.get(id);
    },
    started: Promise.resolve(),
    resetReview() {},
    resetCompactSummary() {},
    loadScan() {},
    refused() {},
    fail(_element, message) { failures.push(message); },
    reason: result => result.body.error,
    download(blob, name) { downloads.push({ blob, name }); },
    async call(path) {
      const [, id, endpoint] = /^\/api\/scans\/([a-f0-9]{16})\/(\w+)$/.exec(path);
      requested.push([id, endpoint]);
      if (id === scanA && endpoint === navigateDuring) {
        paused.resolve();
        await resume.promise;
      }
      if (endpoint === rejectEndpoint) {
        return { r: { ok: false, status: 503 }, body: { error: 'Fixture failure' } };
      }
      return { r: { ok: true, status: 200 }, body: [{ fixture_scan: id, section: endpoint }] };
    },
  });

  vm.runInContext(exporter + '\nsid = fixture.id; scan = fixture;', context);
  const pending = vm.runInContext("$('rawdownload').onclick()", context);
  if (navigateDuring) {
    await Promise.race([
      paused.promise,
      pending.then(() => { throw new Error('Export finished without the expected request'); }),
    ]);
    context.nextScan = scanB;
    vm.runInContext("openScan([nextScan, 'summary', '']);", context);
    resume.resolve();
  }
  await pending;
  assert.equal(dom.get('rawdownload').disabled, false);
  if (rejectEndpoint) {
    assert.equal(downloads.length, 0);
    assert.match(failures[0], /Full TXT export unavailable: HTTP 503/);
    assert.equal(requested.length, 2);
    return;
  }

  assert.deepEqual(failures, []);
  assert.equal(downloads.length, 1);
  assert.match(downloads[0].name, new RegExp('^huntsman-evidence-' + scanA));
  const raw = await downloads[0].blob.text();
  assert.ok(raw.includes('SCAN_ID: ' + scanA));
  function parse(label) {
    const startTag = '[START_' + label + ']\n';
    const endTag = '\n[END_' + label + ']';
    const start = raw.indexOf(startTag);
    const end = raw.indexOf(endTag, start + startTag.length);
    assert.ok(start >= 0 && end >= 0, 'missing or incomplete section ' + label);
    return JSON.parse(raw.slice(start + startTag.length, end));
  }
  assert.equal(parse('SCAN_METADATA').id, scanA);
  assert.deepEqual(
    sections.map(([, label]) => [label, parse(label)[0].fixture_scan]),
    sections.map(([, label]) => [label, scanA]),
    'every section in the generated file must belong to the scan in its header',
  );
}

test('complete export carries the original scan throughout', () => runExport({}));
for (const [navigateDuring] of sections) {
  test('view change during ' + navigateDuring + ' keeps the original scan', () => runExport({ navigateDuring }));
}
test('an endpoint failure aborts the download and re-enables export', () => runExport({ rejectEndpoint: 'correlations' }));
