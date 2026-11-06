'use strict';

// Drives the real HTTP endpoints: configure, replay the requests the payload
// would trigger (in random order), then ask for the token.

process.env.FRAG_SETTLE_MS = '100';

const test = require('node:test');
const assert = require('node:assert/strict');

const { app, PRESETS } = require('../server');
const { generateCSS } = require('../public/payload');
const { SEED, rng, leak, parsePayload } = require('./helpers');

const SETTLE_MS = Number(process.env.FRAG_SETTLE_MS);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let server;
let base;
const realLog = console.log;

test.before(async () => {
  console.log = () => {}; // the server is chatty
  server = app.listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => {
  console.log = realLog;
  server.close();
});

async function configure(user) {
  const res = await fetch(base + '/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(user),
  });
  const config = await res.json();
  return parsePayload(generateCSS(config, base));
}

const send = ({ t, c }) => fetch(`${base}/${t === 'm' ? '' : t + '/'}${c}`).then(r => r.arrayBuffer());
const token = () => fetch(base + '/api/token').then(r => r.json());

async function extract(rules, value, order, { gapMs = 0, settle = true } = {}) {
  const { requests } = leak(rules, value);
  for (const req of order(requests)) {
    await send(req);
    if (gapMs) await sleep(gapMs);
  }
  const early = await token();
  if (!settle) return { early };
  await sleep(SETTLE_MS + 50);
  return { early, final: await token() };
}

const listed = (result, secret) => (result.candidates || [result.token]).includes(secret);

test('anchor with random hex junk, start first', async () => {
  const r = rng(SEED + 10);
  for (const [length, windowSize] of [[8, 3], [17, 4], [32, 3], [40, 4]]) {
    const rules = await configure({ ...PRESETS.anchor, tokenLength: length, windowSize });
    const secret = r.hex(length);
    const value = 'https://example.com/m/callback/email?token=' + secret +
      '&operation=login&state=medium&rememberMe=false&x=' + r.hex(r.int(4, 40));
    const { early, final } = await extract(rules, value, reqs => [
      reqs.find(q => q.t === 's'),
      ...r.shuffle(reqs.filter(q => q.t !== 's')),
    ]);

    assert.equal(early.status, 'partial', 'must not stitch while requests are still arriving');
    assert.equal(final.status, 'ok', JSON.stringify(final));
    assert.ok((final.candidates || [final.token]).includes(secret), `${secret}: ${JSON.stringify(final)}`);
  }
});

test('hidden input, requests overtaking the start are kept', async () => {
  const r = rng(SEED + 11);
  for (const length of [12, 24, 40]) {
    const rules = await configure({ ...PRESETS.hidden, tokenLength: length });
    const secret = r.hex(length);
    const { final } = await extract(rules, secret, reqs => {
      const shuffled = r.shuffle(reqs.filter(q => q.t !== 's'));
      const half = shuffled.length >> 1;
      // Half the burst (including possibly the end) arrives before the start.
      return [...shuffled.slice(0, half), reqs.find(q => q.t === 's'), ...shuffled.slice(half)];
    });

    assert.equal(final.status, 'ok', JSON.stringify(final));
    assert.ok((final.candidates || [final.token]).includes(secret), `${secret}: ${JSON.stringify(final)}`);
  }
});

test('a later extraction does not inherit chunks from an earlier one', async () => {
  const r = rng(SEED + 12);
  const rules = await configure({ ...PRESETS.hidden, tokenLength: 40, windowSize: 4 });
  const first = r.hex(40);
  const second = r.hex(40);
  await extract(rules, first, reqs => reqs);
  const { final } = await extract(rules, second, reqs => reqs);
  // With 4-char windows a clean extraction is almost always unique, so any
  // leftover windows from the first token would show up as a wrong answer.
  assert.ok(listed(final, second), JSON.stringify(final));
});

test('back-to-back extractions with no quiet gap are kept apart', async () => {
  const r = rng(SEED + 13);
  const rules = await configure({ ...PRESETS.hidden, tokenLength: 40, windowSize: 4 });
  const first = r.hex(40);
  const second = r.hex(40);
  const startFirst = reqs => [reqs.find(q => q.t === 's'), ...r.shuffle(reqs.filter(q => q.t !== 's'))];
  await extract(rules, first, startFirst, { settle: false });
  const { early, final } = await extract(rules, second, startFirst);
  // Mid-burst, the server should hold exactly the second burst's windows.
  const windows = leak(rules, second).requests.filter(q => q.t === 'm').length;
  assert.equal(early.chunks, windows, 'chunks from the first burst leaked into the second');
  assert.ok(listed(final, second), JSON.stringify(final));
});

test('a burst longer than the settle time keeps chunks sent before a late start', async () => {
  const r = rng(SEED + 14);
  const rules = await configure({ ...PRESETS.hidden, tokenLength: 40, windowSize: 4 });
  const secret = r.hex(40);
  // Requests trickle in with gaps shorter than SETTLE_MS, but the whole burst
  // lasts several times longer, and the start arrives last.
  const { final } = await extract(rules, secret, reqs => [
    ...r.shuffle(reqs.filter(q => q.t !== 's')),
    reqs.find(q => q.t === 's'),
  ], { gapMs: SETTLE_MS / 4 });
  assert.equal(final.status, 'ok', JSON.stringify(final));
  assert.ok(listed(final, secret), JSON.stringify(final));
});

test('leak routes only accept the lengths the payload uses', async () => {
  for (const path of ['/abcde', '/ab', '/s/abc', '/e/a', '/s/zz']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 404, path);
  }
  for (const path of ['/', '/payload.js']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, path);
  }
});
