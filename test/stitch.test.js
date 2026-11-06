'use strict';

// Randomised end-to-end tests of the stitcher. Each case:
//   1. generates a random hex token of random length,
//   2. embeds it in an anchor href (optionally followed by random hex junk) or
//      a hidden input value,
//   3. works out which requests the real CSS payload (public/payload.js) would
//      trigger for that attribute value,
//   4. shuffles them into a random arrival order and stitches.
//
// Runs are seeded; set FRAG_SEED=<n> to try a different set of tokens.

const test = require('node:test');
const assert = require('node:assert/strict');

const { tryStitch } = require('../lib/stitch');
const { buildConfig, PRESETS } = require('../server');
const { SEED, rng, grams, leak, payloadRules } = require('./helpers');

const MIN_LENGTH = 6;
const MAX_LENGTH = 40;
const TOKENS_PER_LENGTH = 4;

const SCENARIOS = [
  {
    name: 'anchor (preset)',
    type: 'anchor',
    user: PRESETS.anchor,
    value: (token, junk) =>
      'https://example.com/m/callback/email?token=' + token +
      '&operation=login&state=medium&rememberMe=false' + junk,
  },
  {
    name: 'anchor (custom start/end)',
    type: 'anchor',
    user: {
      selector: 'a[href^="https://shop.test/account/reset?"]',
      attribute: 'href',
      tokenName: 'reset code',
      startSelector: 'code=',
      endSelector: '&lang=en',
    },
    value: (token, junk) => 'https://shop.test/account/reset?code=' + token + '&lang=en' + junk,
  },
  {
    name: 'hidden input (preset)',
    type: 'hidden',
    user: PRESETS.hidden,
    value: token => token,
  },
  {
    name: 'hidden input (prefixed value)',
    type: 'hidden',
    user: {
      selector: 'input[type="hidden"][name="state"]',
      attribute: 'value',
      tokenName: 'state',
      startSelector: 'v1:',
      endSelector: ':sig',
    },
    value: token => 'v1:' + token + ':sig',
  },
];

// Random hex junk appended to the end of the href, with a mix of separators
// (including none, so the junk runs straight on from the last param).
function randomJunk(r) {
  const sep = r.pick(['&h=', '&_=', '#', '/', '']);
  return sep + r.hex(r.int(1, 64));
}

const setups = new Map();
function setup(scenario) {
  if (!setups.has(scenario)) {
    const { config, contextHexChunks } = buildConfig({ ...scenario.user, tokenLength: MAX_LENGTH });
    setups.set(scenario, { config, contextHexChunks, rules: payloadRules(config) });
  }
  return setups.get(scenario);
}

function candidatesOf(result) {
  return result ? result.candidates || [result.token] : [];
}

function describeCase(c) {
  return `seed=${SEED} token=${c.token} (${c.token.length} chars)\n  value: ${c.value}\n  ` +
    `result: ${JSON.stringify(c.result)}`;
}

// Every candidate must be a token the leaked data could actually have come
// from. These must hold in every case, junk or not.
function invalidCandidates(c, leakedChunks) {
  const { token, result } = c;
  const problems = [];
  const leaked = new Set(leakedChunks);
  for (const cand of candidatesOf(result)) {
    if (cand.length !== token.length) problems.push(`candidate ${cand} has length ${cand.length}`);
    if (!cand.startsWith(token.slice(0, 3))) problems.push(`candidate ${cand} has the wrong start`);
    if (!cand.endsWith(token.slice(-3))) problems.push(`candidate ${cand} has the wrong end`);
    const foreign = [...grams(cand)].filter(g => !leaked.has(g));
    if (foreign.length) problems.push(`candidate ${cand} uses chunks that never leaked: ${foreign}`);
  }
  return problems;
}

// Why the real token wasn't recovered, or null if it was. With junk, a long
// (truncated) candidate list is acceptable as long as the real token is in it.
function missReason({ token, result }, { allowTruncated }) {
  if (!result) return 'no result';
  if (candidatesOf(result).includes(token)) {
    return result.truncated && !allowTruncated ? 'candidate list was truncated' : null;
  }
  if (result.truncated) return 'real token beyond the truncated candidate list';
  return result.candidates ? 'real token missing from candidates' : `misidentified as ${result.token}`;
}

// Hex junk after the token can occasionally share enough 2-char overlaps with
// it that a segment of junk is interchangeable with a segment of the token, so
// the leaked data no longer pins the token down. Measured over 15k random
// cases the real token is missing from the candidates ~0.2% of the time;
// without junk recovery is exact.
const MIN_JUNK_RECOVERY_RATE = 0.98;

function runScenario(t, scenario, { junk }) {
  const { rules, contextHexChunks } = setup(scenario);
  const r = rng(SEED ^ hash(scenario.name + junk));
  const invalid = [];
  const missed = [];
  let unique = 0;
  let ambiguous = 0;
  let total = 0;

  for (let length = MIN_LENGTH; length <= MAX_LENGTH; length++) {
    for (let i = 0; i < TOKENS_PER_LENGTH; i++) {
      const token = r.hex(length);
      const value = scenario.value(token, junk ? randomJunk(r) : '');
      const { data } = leak(rules, value);
      data.chunks = r.shuffle(data.chunks);

      assert.equal(data.start, token.slice(0, 3), `start chunk for ${value}`);
      assert.equal(data.end, token.slice(-3), `end chunk for ${value}`);

      const result = tryStitch(data, 3, contextHexChunks, length);
      const c = { token, value, result };
      total++;

      const problems = invalidCandidates(c, data.chunks);
      if (problems.length) invalid.push(`${problems.join('; ')}\n  ${describeCase(c)}`);

      const reason = missReason(c, { allowTruncated: junk });
      if (reason) missed.push(`${reason}\n  ${describeCase(c)}`);
      else if (result.candidates) ambiguous++;
      else unique++;
    }
  }

  t.diagnostic(`${total} tokens: ${unique} unique, ${ambiguous} ambiguous with the real token listed, ${missed.length} missed`);
  for (const m of missed) t.diagnostic(`missed: ${m}`);

  assert.equal(invalid.length, 0, `\n${invalid.join('\n\n')}`);
  if (junk) {
    const rate = (total - missed.length) / total;
    assert.ok(rate >= MIN_JUNK_RECOVERY_RATE,
      `recovered ${(rate * 100).toFixed(1)}% (< ${MIN_JUNK_RECOVERY_RATE * 100}%)\n${missed.join('\n\n')}`);
  } else {
    assert.equal(missed.length, 0, `\n${missed.join('\n\n')}`);
  }
}

function hash(s) {
  let h = 0;
  for (const ch of s) h = (Math.imul(h, 31) + ch.charCodeAt(0)) | 0;
  return h;
}

test('random tokens', async t => {
  for (const scenario of SCENARIOS) {
    await t.test(scenario.name, t => runScenario(t, scenario, { junk: false }));
    if (scenario.type === 'anchor') {
      await t.test(`${scenario.name} + random hex junk`, t => runScenario(t, scenario, { junk: true }));
    }
  }
});

test('result does not depend on request arrival order', () => {
  const scenario = SCENARIOS[0];
  const { rules, contextHexChunks } = setup(scenario);
  const r = rng(SEED + 1);
  for (let i = 0; i < 50; i++) {
    const token = r.hex(r.int(MIN_LENGTH, MAX_LENGTH));
    const { data } = leak(rules, scenario.value(token, randomJunk(r)));
    const a = tryStitch({ ...data, chunks: r.shuffle(data.chunks) }, 3, contextHexChunks, token.length);
    const b = tryStitch({ ...data, chunks: r.shuffle(data.chunks) }, 3, contextHexChunks, token.length);
    assert.deepEqual(a, b, `token ${token}`);
  }
});

test('payload leaks exactly the expected requests', () => {
  const scenario = SCENARIOS[0];
  const { rules } = setup(scenario);
  const token = '0123456789abcdef0123456789abcdef01234567';
  const value = scenario.value(token, '&h=deadbeef');
  const { requests } = leak(rules, value);
  const hexGrams = [...grams(value)].filter(g => /^[0-9a-f]{3}$/.test(g)).sort();
  assert.deepEqual(requests.filter(q => q.t === 'm').map(q => q.c).sort(), hexGrams);
  assert.deepEqual(requests.filter(q => q.t !== 'm'), [{ t: 's', c: '012' }, { t: 'e', c: '567' }]);
});

// Cases the previous stitcher got wrong, found while investigating.
test('regressions', async t => {
  const anchor = SCENARIOS[0];
  const { rules, contextHexChunks } = setup(anchor);
  const stitch = (token, junk = '') => {
    const { data } = leak(rules, anchor.value(token, junk));
    return { data, result: tryStitch(data, 3, contextHexChunks, token.length) };
  };

  await t.test('interleaved repeats are reported as ambiguous, not guessed', () => {
    // "c4" occurs three times, so several tokens leak identical chunk sets.
    // The old stitcher confidently returned 54392c484edbc437dc48536e.
    const token = '5437dc4392c484edbc48536e';
    const { result } = stitch(token);
    assert.ok(result.candidates.includes(token));
    assert.ok(result.candidates.includes('54392c484edbc437dc48536e'));
    const key = s => [...grams(s)].sort().join();
    for (const c of result.candidates) assert.equal(key(c), key(token), `${c} leaks different chunks`);
  });

  await t.test('chunks "abc" and "aae" are leaked (payload variable collision)', () => {
    // These used to share --s/--e with the start/end URLs and never leaked.
    for (const token of ['ab1abc23aae4567f', 'abc0123456789aae', '9f8aae7abc6d5e4c']) {
      const { data, result } = stitch(token);
      assert.equal(data.start, token.slice(0, 3));
      assert.ok(data.chunks.includes('abc') && data.chunks.includes('aae'), JSON.stringify(data));
      assert.equal(result.token, token);
    }
  });

  await t.test('junk that links into the token graph is not spliced in', () => {
    // Old stitcher returned 46+ char candidates containing the junk.
    const { result } = stitch('cf322fd6f165e1a690f47fc9', '&h=70fdeee1bb151750b64c5fac4892265ad');
    assert.equal(result.token, 'cf322fd6f165e1a690f47fc9');
    assert.equal(result.candidates, undefined);
  });

  await t.test('junk sharing a context chunk ("bac" from "callback")', () => {
    const token = 'f5db2c20b657fcc0b7905e4054826bfd';
    const { result } = stitch(token, '&h=8e8b590dd3eca3f9c76b23ba8bac1f9176909c105');
    assert.ok(candidatesOf(result).includes(token), JSON.stringify(result));
  });

  await t.test('runs of a repeated character (self-loops)', () => {
    for (const token of ['a0000000000b', '00000000', 'f0f0f0f0f0f0', '1234444444444321']) {
      const { result } = stitch(token);
      assert.equal(result.token, token);
      assert.equal(result.candidates, undefined);
    }
  });

  await t.test('never returns candidates of the wrong length', () => {
    const { result } = stitch('98753000236acac3b09afa9757faf872', '&h=b68790f531015ce691f380a3dab67481af555379b4');
    for (const c of candidatesOf(result)) assert.equal(c.length, 32);
    assert.ok(candidatesOf(result).includes('98753000236acac3b09afa9757faf872'));
  });
});

test('incomplete data', async t => {
  await t.test('missing start or end gives no result', () => {
    assert.equal(tryStitch({ start: 'abc', end: null, chunks: ['abc'] }, 3, new Set(), 10), null);
    assert.equal(tryStitch({ start: null, end: 'abc', chunks: ['abc'] }, 3, new Set(), 10), null);
  });

  await t.test('a missing chunk that breaks the path gives no result', () => {
    const token = '0123456789abcdef';
    const chunks = [...grams(token)].filter(g => g !== '789');
    assert.equal(tryStitch({ start: '012', end: 'def', chunks }, 3, new Set(), token.length), null);
  });
});

test('long tokens: a single answer is only given when it is certain', () => {
  // With 3-char windows, long tokens are usually ambiguous. Whatever happens,
  // a lone token (no candidates list) must be the real one.
  const r = rng(SEED + 2);
  for (const length of [64, 100]) {
    for (let i = 0; i < 3; i++) {
      const token = r.hex(length);
      const result = tryStitch({ start: token.slice(0, 3), end: token.slice(-3), chunks: [...grams(token)] }, 3, new Set(), length);
      assert.ok(result, token);
      if (!result.candidates) assert.equal(result.token, token);
      else if (!result.truncated) assert.ok(result.candidates.includes(token), token);
    }
  }
});

test('unknown token length picks the shortest full explanation', () => {
  const token = '3f9a07c1e2b4d856';
  const result = tryStitch({ start: '3f9', end: '856', chunks: [...grams(token)] }, 3, new Set(), 0);
  assert.equal(result.token, token);
});
