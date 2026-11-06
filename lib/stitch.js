'use strict';

// Token reconstruction from leaked fixed-size chunks.
//
// The CSS payload leaks:
//   - start:  the first `windowSize` chars of the token
//   - end:    the last `windowSize` chars of the token
//   - chunks: the *set* of every hex `windowSize`-gram present anywhere in the
//             attribute value: token chunks plus hex noise from the rest of the
//             value (e.g. "bac" from "callback", or junk query parameters).
//
// Chunk multiplicities and positions are not leaked, so several different
// tokens can produce exactly the same data, and noise chunks can link into the
// token's graph. We therefore enumerate tokens of the expected length that:
//   1. start with `start` and end with `end`,
//   2. only contain chunks that were actually leaked,
// and rank them by how cheaply the chunks they *don't* use can be explained as
// noise: leftover chunks forming one contiguous run (a single junk string) are
// cheap, while a token that skips a stretch of the real token to detour
// through junk leaves extra fragments behind and is penalised. Known context
// chunks are always free to leave over. If several tokens tie, every one of
// them is returned as a candidate, because the leaked data genuinely cannot
// tell them apart.

const DEFAULT_MAX_CANDIDATES = 64;
const DEFAULT_MAX_STEPS = 2_000_000;
// How many chunks below the best coverage a walk may be and still be ranked.
// Junk can only beat the real token on coverage by re-using the slack from the
// token's own repeated chunks, which is small in practice.
const COVERAGE_MARGIN = 2;
const MAX_RANKED = 20_000;

function tryStitch(data, windowSize = 3, contextChunks = new Set(), tokenLength = 0, opts = {}) {
  const COST_TOLERANCE = opts.costTolerance ?? windowSize - 1;
  const maxCandidates = opts.maxCandidates || DEFAULT_MAX_CANDIDATES;
  const maxSteps = opts.maxSteps || DEFAULT_MAX_STEPS;

  if (!data || !data.start || !data.end) return null;

  const k = windowSize;
  const edgeSize = k - 1;
  const hexPattern = new RegExp('^[0-9a-f]{' + k + '}$');
  const { start, end } = data;
  if (!hexPattern.test(start) || !hexPattern.test(end)) return null;

  // Sorted so the result never depends on request arrival order.
  const chunks = [...new Set([...(data.chunks || []), start, end])]
    .filter(c => hexPattern.test(c))
    .sort();

  const prefix = c => c.substring(0, edgeSize);
  const suffix = c => c.substring(c.length - edgeSize);

  const outEdges = new Map();
  const inEdges = new Map();
  for (const c of chunks) {
    if (!outEdges.has(prefix(c))) outEdges.set(prefix(c), []);
    outEdges.get(prefix(c)).push(c);
    if (!inEdges.has(suffix(c))) inEdges.set(suffix(c), []);
    inEdges.get(suffix(c)).push(c);
  }

  // Minimum number of edges from each node to the node the end chunk leaves
  // from; used to prune walks that can no longer finish on time.
  const endFrom = prefix(end);
  const distToEndFrom = new Map([[endFrom, 0]]);
  const queue = [endFrom];
  while (queue.length) {
    const node = queue.shift();
    const d = distToEndFrom.get(node);
    for (const c of inEdges.get(node) || []) {
      const from = prefix(c);
      if (!distToEndFrom.has(from)) {
        distToEndFrom.set(from, d + 1);
        queue.push(from);
      }
    }
  }
  if (!distToEndFrom.has(suffix(start)) && start !== end) return null;

  // Chunks we expect to see outside the token (from the known prefix/suffix)
  // don't need explaining, so they neither earn coverage nor cost anything.
  const weight = c => (contextChunks.has(c) ? 0 : 1);
  const unexplained = chunks.filter(c => weight(c) === 1);

  // Approximate number of junk characters needed to produce the chunks a
  // candidate leaves unused: each run of chunks costs one char per chunk plus
  // (windowSize - 1) to start it. Runs = minimum trails covering the leftover
  // edges, i.e. per weakly-connected component max(1, sum of out-in surplus).
  function leftoverCost(token) {
    const own = new Set();
    for (let i = 0; i + k <= token.length; i++) own.add(token.substring(i, i + k));
    const left = unexplained.filter(c => !own.has(c));
    if (!left.length) return 0;

    const parent = new Map();
    const find = x => {
      while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); }
      return x;
    };
    const balance = new Map();
    for (const c of left) {
      const a = prefix(c), b = suffix(c);
      if (!parent.has(a)) parent.set(a, a);
      if (!parent.has(b)) parent.set(b, b);
      parent.set(find(a), find(b));
      balance.set(a, (balance.get(a) || 0) + 1);
      balance.set(b, (balance.get(b) || 0) - 1);
    }
    const surplus = new Map();
    for (const [node, bal] of balance) {
      const root = find(node);
      surplus.set(root, (surplus.get(root) || 0) + Math.max(0, bal));
    }
    let runs = 0;
    for (const s of surplus.values()) runs += Math.max(1, s);
    return left.length + runs * edgeSize;
  }

  function search(length) {
    const edgeCount = length - k + 1; // number of chunks in a token of this length
    if (edgeCount < 1) return null;

    const used = new Map([[start, 1]]);
    const walk = [start]; // token text: start chunk, then one char per chunk
    const path = [start]; // chunks in walk order
    let score = weight(start);

    let best = -1;
    let found = []; // { token, score } with score >= best - COVERAGE_MARGIN
    let truncated = false;
    let steps = 0;

    function dfs(remaining) {
      if (++steps > maxSteps) { truncated = true; return; }
      const last = path[path.length - 1];

      if (remaining === 0) {
        if (last !== end) return;
        if (score > best) {
          best = score;
          found = found.filter(f => f.score >= best - COVERAGE_MARGIN);
        }
        if (found.length < MAX_RANKED) found.push({ token: walk.join(''), score });
        else truncated = true;
        return;
      }

      // Each further chunk can raise the score by at most one.
      if (score + remaining < best - COVERAGE_MARGIN) return;

      const node = suffix(last);
      const d = distToEndFrom.get(node);
      if (d === undefined || d > remaining - 1) return;

      const next = outEdges.get(node) || [];
      // Try new chunks first so a good bound is found quickly.
      const ordered = next.filter(c => !used.has(c)).concat(next.filter(c => used.has(c)));
      for (const c of ordered) {
        const isNew = !used.has(c);
        used.set(c, (used.get(c) || 0) + 1);
        if (isNew) score += weight(c);
        walk.push(c[c.length - 1]);
        path.push(c);

        dfs(remaining - 1);

        path.pop();
        walk.pop();
        if (isNew) { score -= weight(c); used.delete(c); }
        else used.set(c, used.get(c) - 1);
        if (steps > maxSteps) return;
      }
    }

    dfs(edgeCount - 1);
    if (!found.length) return null;

    // The cost is an estimate (junk strings could also pass through chunks the
    // token uses), so treat anything within COST_TOLERANCE of the best as a
    // tie. That's still below the cost of skipping even one real chunk when
    // there's no junk (1 + edgeSize), so clean extractions stay unambiguous.
    const ranked = found
      .map(f => ({ token: f.token, cost: leftoverCost(f.token) }))
      .sort((a, b) => a.cost - b.cost || (a.token < b.token ? -1 : 1));
    const bestCost = ranked[0].cost;
    let tokens = ranked.filter(f => f.cost <= bestCost + COST_TOLERANCE).map(f => f.token);
    if (tokens.length > maxCandidates) {
      tokens = tokens.slice(0, maxCandidates);
      truncated = true;
    }
    return { cost: bestCost, tokens, truncated };
  }

  let result = null;
  if (tokenLength > 0) {
    result = search(tokenLength);
  } else {
    // Unknown length: take the shortest length that leaves the least to explain.
    const minLength = k + (start === end ? 0 : (distToEndFrom.get(suffix(start)) || 0) + 1);
    const maxLength = chunks.length + k + 3;
    for (let len = minLength; len <= maxLength; len++) {
      const r = search(len);
      if (r && (!result || r.cost < result.cost)) result = r;
      if (result && result.cost === 0) break;
    }
  }

  if (!result) return null;

  const [token] = result.tokens;
  const out = { token, length: token.length };
  if (result.tokens.length > 1 || result.truncated) out.candidates = result.tokens;
  if (result.truncated) out.truncated = true;
  return out;
}

module.exports = { tryStitch };
