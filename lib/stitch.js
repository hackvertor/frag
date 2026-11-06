'use strict';

// Token reconstruction from leaked substrings.
//
// The CSS payload leaks:
//   - start:  the first few chars of the token
//   - end:    the last few chars of the token
//   - chunks: the *set* of every hex `windowSize`-char substring present
//             anywhere in the attribute value: the token's own windows plus
//             any hex noise from the rest of the value (e.g. "bac" from
//             "callback", or junk query parameters).
//
// Positions and repeat counts are not leaked, so we search for every token of
// the configured length that matches the start and end and only contains
// leaked windows, building it one char at a time. Candidates are ranked by how
// cheaply the leaked windows they *don't* use can be explained as junk: a
// single contiguous run of leftovers is cheap, while a token that skips part
// of the real token to detour through junk leaves extra fragments behind. If
// several tokens remain equally plausible, all of them are returned, because
// the leaked data genuinely can't tell them apart.

const HEX = '0123456789abcdef';

// Walks may cover up to this many fewer windows than the best walk and still
// be ranked: junk can only beat the real token on coverage by using the slack
// from the token's own repeated windows, which is small.
const COVERAGE_MARGIN = 2;
const MAX_RANKED = 20_000;

function tryStitch(data, opts = {}) {
  const {
    windowSize: k = 3,
    tokenLength: length,
    context = new Set(),
    maxCandidates = 64,
    maxSteps = 2_000_000,
  } = opts;
  const { start, end } = data || {};
  if (!start || !end || !length || length < Math.max(k, start.length, end.length)) return null;

  const isWindow = new RegExp(`^[${HEX}]{${k}}$`);
  const leaked = new Set((data.chunks || []).filter(c => isWindow.test(c)));
  // Windows from the known text around the token are expected leftovers.
  const weight = w => (context.has(w) ? 0 : 1);

  // --- search ---------------------------------------------------------------

  // Fewest further chars needed from each (k - 1)-char state to finish on the
  // known end, so walks that can no longer get there in time are cut early.
  const node = s => s.slice(-(k - 1));
  const isFinal = n => (end.length >= k - 1 ? n === node(end) : n.endsWith(end));
  const finish = new Map();
  for (const w of leaked) {
    if (isFinal(node(w))) finish.set(node(w), 0);
  }
  const into = new Map();
  for (const w of leaked) {
    const to = node(w);
    if (!into.has(to)) into.set(to, []);
    into.get(to).push(w.slice(0, -1));
  }
  const queue = [...finish.keys()];
  while (queue.length) {
    const to = queue.shift();
    for (const from of into.get(to) || []) {
      if (!finish.has(from)) {
        finish.set(from, finish.get(to) + 1);
        queue.push(from);
      }
    }
  }

  const used = new Map();
  let token = '';
  let score = 0;
  let best = -1;
  let found = [];
  let steps = 0;
  let truncated = false;

  function push(c) {
    const next = token + c;
    if (next.length >= k) {
      const w = next.slice(-k);
      if (!leaked.has(w)) return false;
      const n = used.get(w) || 0;
      used.set(w, n + 1);
      if (n === 0) score += weight(w);
    }
    token = next;
    return true;
  }

  function pop() {
    if (token.length >= k) {
      const w = token.slice(-k);
      const n = used.get(w);
      if (n === 1) { used.delete(w); score -= weight(w); } else used.set(w, n - 1);
    }
    token = token.slice(0, -1);
  }

  function dfs() {
    if (++steps > maxSteps) { truncated = true; return; }
    const remaining = length - token.length;
    if (remaining === 0) {
      if (score > best) {
        best = score;
        found = found.filter(f => f.score >= best - COVERAGE_MARGIN);
      }
      if (found.length < MAX_RANKED) found.push({ token, score });
      else truncated = true;
      return;
    }
    // Each further char can cover at most one new window.
    if (score + remaining < best - COVERAGE_MARGIN) return;
    if (token.length >= k - 1 && !(finish.get(node(token)) <= remaining)) return;

    const endIndex = token.length - (length - end.length);
    for (const c of endIndex >= 0 ? end[endIndex] : HEX) {
      if (push(c)) { dfs(); pop(); }
      if (steps > maxSteps) return;
    }
  }

  for (const c of start) {
    if (!push(c)) return null;
  }
  dfs();
  if (!found.length) return null;

  // --- ranking --------------------------------------------------------------

  // Approximate junk chars needed to produce the windows a candidate leaves
  // unused: one char per window plus (k - 1) to start each run, where runs =
  // the minimum number of trails covering the leftover windows (per connected
  // component, the larger of 1 and the total out/in surplus).
  const unexplained = [...leaked].filter(w => weight(w) === 1);
  function leftoverCost(candidate) {
    const own = new Set();
    for (let i = 0; i + k <= candidate.length; i++) own.add(candidate.slice(i, i + k));
    const left = unexplained.filter(w => !own.has(w));
    if (!left.length) return 0;

    const parent = new Map();
    const find = x => {
      while (parent.get(x) !== x) x = parent.get(x);
      return x;
    };
    const balance = new Map();
    for (const w of left) {
      const a = w.slice(0, -1);
      const b = w.slice(1);
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
    return left.length + runs * (k - 1);
  }

  // The cost is an estimate (real junk can pass through windows the token also
  // uses), so anything within k - 1 of the best is a tie. That's still less
  // than skipping a single real window when there's no junk (1 + (k - 1)), so
  // clean extractions stay unambiguous.
  const ranked = found
    .map(f => ({ token: f.token, cost: leftoverCost(f.token) }))
    .sort((a, b) => a.cost - b.cost || (a.token < b.token ? -1 : 1));
  let tokens = ranked.filter(f => f.cost <= ranked[0].cost + (k - 1)).map(f => f.token);
  if (tokens.length > maxCandidates) {
    tokens = tokens.slice(0, maxCandidates);
    truncated = true;
  }

  const result = { token: tokens[0], length };
  if (tokens.length > 1 || truncated) result.candidates = tokens;
  if (truncated) result.truncated = true;
  return result;
}

module.exports = { tryStitch };
