'use strict';

// Randomised end-to-end tests of the solver. Each case:
//   1. generates a random token of random length (hex, or each other charset),
//   2. embeds it in an anchor href (optionally followed by random junk in the
//      same charset) or a hidden input value,
//   3. works out which requests the real CSS payload (public/payload.js) would
//      trigger for that attribute value,
//   4. shuffles them into a random arrival order and stitches.
//
// Runs are seeded; set FRAG_SEED=<n> to try a different set of tokens.

const test = require('node:test');
const assert = require('node:assert/strict');

const { tryStitch, stitchCharset, assignCase } = require('../lib/stitch');
const P = require('../public/payload');
const { buildConfig, PRESETS } = require('../server');
const { SEED, ANCHOR_LENGTH, rng, grams, leak, payloadRules } = require('./helpers');

const MIN_LENGTH = 6;
const MAX_LENGTH = 40;
const TOKENS_PER_LENGTH = 4;

// Expected accuracy, measured over thousands of random runs (see README).
//  - 4-char windows: a single, correct answer >= 99% of the time; without junk
//    the real token is always listed.
//  - 3-char windows: smaller CSS, but longer tokens are often ambiguous, and
//    occasionally (~1 in 7,000 clean tokens) there are more candidates than
//    the list holds.
//  - Hex junk after the token can share enough overlaps with it that segments
//    become interchangeable, so the real token can fall out of the list.
const EXPECT = {
  4: { cleanListed: 1, junkListed: 0.99, singleGuess: 0.99 },
  3: { cleanListed: 0.99, junkListed: 0.97, singleGuess: 0.75 },
};
// Non-hex charsets (3-char windows only): the case-insensitive windows are
// as sparse as hex 4-char ones (36-39 symbols cubed vs 16^4), and letter
// case is resolved from the case pairs in all but rare ties.
const CHARSET_EXPECT = { cleanListed: 0.99, junkListed: 0.97, singleGuess: 0.95 };
const CASED = ['alnum', 'base64', 'base64url'];

// The chars random tokens and junk are drawn from. Base64 padding only ever
// ends a value, so it's left out of random tokens.
const tokenAlphabet = charset =>
  P.alphabetOf(P.charsetOf(charset)).replace(charset === 'base64' ? '=' : '', '');

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

// Random junk appended to the end of the href, with a mix of separators
// (including none, so the junk runs straight on from the last param).
function randomJunk(r, charset = 'hex') {
  return r.pick(['&h=', '&_=', '#', '/', '']) + r.chars(tokenAlphabet(charset), r.int(1, 64));
}

const setups = new Map();
function setup(scenario, windowSize, charset = 'hex') {
  const key = scenario.name + windowSize + charset;
  if (!setups.has(key)) {
    const { config, contextChunks, contextCasePairs } = buildConfig({ ...scenario.user, windowSize, charset });
    setups.set(key, { config, context: contextChunks, caseContext: contextCasePairs, rules: payloadRules(config) });
  }
  return setups.get(key);
}

function stitch(scenario, windowSize, token, junk = '') {
  const { rules, context } = setup(scenario, windowSize);
  const value = scenario.value(token, junk);
  const { data } = leak(rules, value);
  const result = tryStitch(data, { windowSize, tokenLength: token.length, context });
  return { value, data, result };
}

const candidatesOf = result => (result ? result.candidates || [result.token] : []);

function describeCase({ token, value, result }) {
  return `seed=${SEED} token=${token} (${token.length} chars)\n  value: ${value}\n  ` +
    `result: ${JSON.stringify(result)}`;
}

// Every candidate must be a token the leaked data could have come from. For
// non-hex charsets windows and anchors are compared lowercased, and every
// case pair must have leaked too.
function invalidCandidates({ token, result }, data, windowSize, cased = false) {
  const problems = [];
  const fold = s => (cased ? s.toLowerCase() : s);
  const leaked = new Set(data.chunks);
  const pairs = new Set(data.pairs);
  for (const cand of candidatesOf(result)) {
    if (cand.length !== token.length) problems.push(`candidate ${cand} has length ${cand.length}`);
    if (!fold(cand).startsWith(fold(token.slice(0, ANCHOR_LENGTH)))) problems.push(`candidate ${cand} has the wrong start`);
    if (!fold(cand).endsWith(fold(token.slice(-ANCHOR_LENGTH)))) problems.push(`candidate ${cand} has the wrong end`);
    const foreign = [...grams(fold(cand), windowSize)].filter(g => !leaked.has(g));
    if (foreign.length) problems.push(`candidate ${cand} uses windows that never leaked: ${foreign}`);
    if (cased && !result.caseUnresolved) {
      const unleaked = [...grams(cand, 2)].filter(g => /[a-z]/i.test(g) && !pairs.has(g));
      if (unleaked.length) problems.push(`candidate ${cand} uses case pairs that never leaked: ${unleaked}`);
    }
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

function runScenario(t, scenario, windowSize, junk, totals, charset = 'hex', expect = EXPECT[windowSize]) {
  const r = rng(SEED ^ hash(scenario.name + junk + windowSize + (charset === 'hex' ? '' : charset)));
  const cs = P.charsetOf(charset);
  const fold = s => (cs.cased ? s.toLowerCase() : s);
  const alphabet = tokenAlphabet(charset);
  const invalid = [];
  const missed = [];
  let single = 0;
  let total = 0;

  for (let length = MIN_LENGTH; length <= MAX_LENGTH; length++) {
    for (let i = 0; i < TOKENS_PER_LENGTH; i++) {
      const token = r.chars(alphabet, length);
      const { rules, context, caseContext } = setup(scenario, windowSize, charset);
      const value = scenario.value(token, junk ? randomJunk(r, charset) : '');
      const { data } = leak(rules, value);
      data.chunks = r.shuffle(data.chunks);

      assert.equal(data.start, fold(token.slice(0, ANCHOR_LENGTH)), `start for ${value}`);
      assert.equal(data.end, fold(token.slice(-ANCHOR_LENGTH)), `end for ${value}`);

      const result = stitchCharset(data, { charset: cs, windowSize, tokenLength: length, context, caseContext });
      const c = { token, value, result };
      total++;

      const problems = invalidCandidates(c, data, windowSize, cs.cased);
      if (problems.length) invalid.push(`${problems.join('; ')}\n  ${describeCase(c)}`);

      const reason = missReason(c, { allowTruncated: junk || windowSize === 3 });
      if (reason) missed.push(`${reason}\n  ${describeCase(c)}`);
      if (result && !result.candidates && result.token === token) single++;
    }
  }

  totals.single += single;
  totals.total += total;
  t.diagnostic(`${total} tokens: ${single} single correct guess, ${total - single - missed.length} ` +
    `ambiguous with the real token listed, ${missed.length} missed`);
  for (const m of missed) t.diagnostic(`missed: ${m}`);

  assert.equal(invalid.length, 0, `\n${invalid.join('\n\n')}`);
  const rate = (total - missed.length) / total;
  const min = expect[junk ? 'junkListed' : 'cleanListed'];
  assert.ok(rate >= min, `real token listed ${(rate * 100).toFixed(1)}% (< ${min * 100}%)\n${missed.join('\n\n')}`);
}

function hash(s) {
  let h = 0;
  for (const ch of s) h = (Math.imul(h, 31) + ch.charCodeAt(0)) | 0;
  return h;
}

for (const windowSize of [4, 3]) {
  test(`random tokens, ${windowSize}-char windows`, async t => {
    const totals = { single: 0, total: 0 };
    for (const scenario of SCENARIOS) {
      await t.test(scenario.name, t => runScenario(t, scenario, windowSize, false, totals));
      if (scenario.type === 'anchor') {
        await t.test(`${scenario.name} + random hex junk`, t => runScenario(t, scenario, windowSize, true, totals));
      }
    }
    const rate = totals.single / totals.total;
    t.diagnostic(`single correct guess: ${(rate * 100).toFixed(1)}% of ${totals.total}`);
    assert.ok(rate >= EXPECT[windowSize].singleGuess,
      `single correct guess ${(rate * 100).toFixed(1)}% (< ${EXPECT[windowSize].singleGuess * 100}%)`);
  });
}

for (const charset of CASED) {
  test(`random ${charset} tokens, 3-char windows`, async t => {
    const totals = { single: 0, total: 0 };
    for (const scenario of SCENARIOS) {
      await t.test(scenario.name, t => runScenario(t, scenario, 3, false, totals, charset, CHARSET_EXPECT));
      if (scenario.type === 'anchor') {
        await t.test(`${scenario.name} + random ${charset} junk`,
          t => runScenario(t, scenario, 3, true, totals, charset, CHARSET_EXPECT));
      }
    }
    const rate = totals.single / totals.total;
    t.diagnostic(`single correct guess: ${(rate * 100).toFixed(1)}% of ${totals.total}`);
    assert.ok(rate >= CHARSET_EXPECT.singleGuess,
      `single correct guess ${(rate * 100).toFixed(1)}% (< ${CHARSET_EXPECT.singleGuess * 100}%)`);
  });
}

test('result does not depend on request arrival order', () => {
  const r = rng(SEED + 1);
  for (const windowSize of [3, 4]) {
    const { rules, context } = setup(SCENARIOS[0], windowSize);
    for (let i = 0; i < 30; i++) {
      const token = r.hex(r.int(MIN_LENGTH, MAX_LENGTH));
      const { data } = leak(rules, SCENARIOS[0].value(token, randomJunk(r)));
      const opts = { windowSize, tokenLength: token.length, context };
      const a = tryStitch({ ...data, chunks: r.shuffle(data.chunks) }, opts);
      const b = tryStitch({ ...data, chunks: r.shuffle(data.chunks) }, opts);
      assert.deepEqual(a, b, `token ${token}`);
    }
  }
});

test('payload leaks exactly the expected requests', () => {
  const token = '0123456789abcdef0123456789abcdef01234567';
  const junk = '&h=deadbeef';
  for (const windowSize of [3, 4]) {
    const { rules } = setup(SCENARIOS[0], windowSize);
    const value = SCENARIOS[0].value(token, junk);
    const { requests } = leak(rules, value);
    const windows = [...grams(value, windowSize)].filter(g => /^[0-9a-f]+$/.test(g)).sort();
    assert.deepEqual(requests.filter(q => q.t === 'm').map(q => q.c).sort(), windows);
    assert.deepEqual(requests.filter(q => q.t !== 'm'), [{ t: 's', c: '01' }, { t: 'e', c: '67' }]);
  }
});

// Cases found while investigating misidentified tokens.
test('regressions', async t => {
  const anchor = SCENARIOS[0];

  await t.test('interleaved repeats: ambiguous with 3-char windows, solved with 4', () => {
    // "c4" occurs three times, so with 3-char windows several tokens leak
    // identical data. The original stitcher confidently returned
    // 54392c484edbc437dc48536e.
    const token = '5437dc4392c484edbc48536e';
    const three = stitch(anchor, 3, token).result;
    assert.ok(three.candidates.includes(token));
    assert.ok(three.candidates.includes('54392c484edbc437dc48536e'));
    const key = s => [...grams(s, 3)].sort().join();
    for (const c of three.candidates) assert.equal(key(c), key(token), `${c} leaks different windows`);

    const four = stitch(anchor, 4, token).result;
    assert.equal(four.token, token);
    assert.equal(four.candidates, undefined);
  });

  await t.test('windows "abc" and "aae" are leaked (payload property collision)', () => {
    // These used to share --s/--e with the start/end URLs and never leaked.
    for (const token of ['ab1abc23aae4567f', 'abc0123456789aae', '9f8aae7abc6d5e4c', 'aa1d3abc093aae7b']) {
      const { data, result } = stitch(anchor, 3, token);
      assert.equal(data.start, token.slice(0, ANCHOR_LENGTH));
      assert.ok(data.chunks.includes('abc') && data.chunks.includes('aae'), JSON.stringify(data));
      assert.equal(result.token, token);
    }
  });

  for (const windowSize of [3, 4]) {
    await t.test(`junk that links into the token graph is not spliced in (${windowSize}-char)`, () => {
      // The original stitcher returned 46+ char candidates containing the junk.
      const { result } = stitch(anchor, windowSize, 'cf322fd6f165e1a690f47fc9', '&h=70fdeee1bb151750b64c5fac4892265ad');
      assert.equal(result.token, 'cf322fd6f165e1a690f47fc9');
      assert.equal(result.candidates, undefined);
    });

    await t.test(`runs of a repeated character (${windowSize}-char)`, () => {
      for (const token of ['a0000000000b', '00000000', 'f0f0f0f0f0f0', '1234444444444321']) {
        const { result } = stitch(anchor, windowSize, token);
        assert.equal(result.token, token);
        assert.equal(result.candidates, undefined);
      }
    });
  }

  await t.test('junk sharing a context window ("bac" from "callback")', () => {
    const token = 'f5db2c20b657fcc0b7905e4054826bfd';
    const { result } = stitch(anchor, 3, token, '&h=8e8b590dd3eca3f9c76b23ba8bac1f9176909c105');
    assert.ok(candidatesOf(result).includes(token), JSON.stringify(result));
  });
});

test('incomplete data gives no result rather than a wrong one', async t => {
  await t.test('missing start or end', () => {
    assert.equal(tryStitch({ start: 'ab', end: null, chunks: ['abc'] }, { tokenLength: 10 }), null);
    assert.equal(tryStitch({ start: null, end: 'bc', chunks: ['abc'] }, { tokenLength: 10 }), null);
  });

  await t.test('a missing window that breaks the path', () => {
    const token = '0123456789abcdef';
    for (const windowSize of [3, 4]) {
      const chunks = [...grams(token, windowSize)].filter(g => !g.includes('78'));
      assert.equal(tryStitch({ start: '01', end: 'ef', chunks }, { windowSize, tokenLength: token.length }), null);
    }
  });
});

test('long tokens: a single answer is only given when it is certain', () => {
  // A lone token (no candidates list) must always be the real one.
  const r = rng(SEED + 2);
  for (const windowSize of [3, 4]) {
    for (const length of [64, 100]) {
      for (let i = 0; i < 3; i++) {
        const token = r.hex(length);
        const data = { start: token.slice(0, 2), end: token.slice(-2), chunks: [...grams(token, windowSize)] };
        const result = tryStitch(data, { windowSize, tokenLength: length });
        assert.ok(result, token);
        if (!result.candidates) assert.equal(result.token, token);
        else if (!result.truncated) assert.ok(result.candidates.includes(token), token);
      }
    }
  }
});

test('payload spreads background layers so Chrome does not crash', () => {
  // A single box with ~65k background layers crashes the tab in Chrome (32k
  // was fine), so the 4-char payload must split its layers across boxes.
  const { generateCSS } = require('../public/payload');
  for (const windowSize of [3, 4]) {
    const { config } = setup(SCENARIOS[0], windowSize);
    const css = generateCSS(config, 'http://frag.test');
    const boxes = css.match(/background:[^;}]*/g).map(b => b.match(/var\(--/g).length);
    assert.equal(boxes.reduce((a, b) => a + b), 16 ** windowSize + 2, 'every window plus start and end');
    for (const n of boxes) assert.ok(n <= 25000, `${n} layers in one box`);
  }
});

test('non-hex payloads leak lowercased windows, case pairs, and nothing else', () => {
  const token = 'Ab9/xY+z0Qq=';
  const junk = '&h=KeY';
  const { rules } = setup(SCENARIOS[0], 3, 'base64');
  const value = SCENARIOS[0].value(token, junk);
  const { requests, data } = leak(rules, value);
  const fold = P.CHARSETS.base64.fold;
  const lower = value.toLowerCase();
  const windows = [...grams(lower, 3)].filter(g => [...g].every(c => fold.includes(c))).sort();
  assert.deepEqual(data.chunks.sort(), windows);
  const alphabet = P.alphabetOf(P.CHARSETS.base64);
  const pairs = [...grams(value, 2)].filter(g => [...g].every(c => alphabet.includes(c)) && /[a-z]/i.test(g)).sort();
  assert.deepEqual(data.pairs.sort(), pairs);
  assert.deepEqual(requests.filter(q => q.t === 's' || q.t === 'e'), [{ t: 's', c: 'ab' }, { t: 'e', c: 'q=' }]);
});

test('letter case is recovered from the case pairs', async t => {
  const pairsOf = s => [...grams(s, 2)].filter(g => /[a-z]/i.test(g));

  await t.test('a clean token', () => {
    const token = 'aB3cDeF9gH';
    assert.deepEqual(assignCase([token.toLowerCase()], pairsOf(token)), { tokens: [token], truncated: false });
  });

  await t.test('digits and symbols between letters keep the case independent', () => {
    const token = 'A1b2C3d4+E/f';
    assert.deepEqual(assignCase([token.toLowerCase()], pairsOf(token)).tokens, [token]);
  });

  await t.test('pairs that genuinely allow both cases give candidates', () => {
    // "xa" and "ay" leak from elsewhere in the token, as do "xA" and "Ay", so
    // the middle "a" can be either case and both leave nothing unexplained.
    const tokens = assignCase(['xayqxay'], ['xa', 'ay', 'xA', 'Ay', 'yq', 'qx']).tokens;
    assert.ok(tokens.includes('xAyqxay') && tokens.includes('xayqxAy'), JSON.stringify(tokens));
  });

  await t.test('a casing that leaves the token\'s own pairs unexplained is ranked down', () => {
    // "aBaB" only uses leaked pairs too, but then nothing in the token
    // explains the leaked "ab".
    assert.deepEqual(assignCase(['abab'], pairsOf('aBab')).tokens, ['aBab']);
  });

  await t.test('a lowercase copy of part of the token elsewhere gives candidates, not a wrong answer', () => {
    // The page also contains "login": token "xLoGiNx" with junk "login" leaks
    // exactly what "xLogiNx" with junk "loGin" would, so both are listed.
    const token = 'xLoGiNx';
    const tokens = assignCase([token.toLowerCase()], [...pairsOf(token), ...pairsOf('login')]).tokens;
    assert.ok(tokens.includes(token), JSON.stringify(tokens));
    assert.ok(tokens.length > 1);
  });

  await t.test('known context pairs are expected leftovers', () => {
    const token = 'tokEN';
    const context = new Set(pairsOf('TOKEN'));
    const pairs = [...pairsOf(token), ...context];
    // Without context, "TO"/"OK" look like the token's own unused pairs.
    assert.deepEqual(assignCase([token.toLowerCase()], pairs, { context }).tokens, [token]);
  });

  await t.test('no consistent casing falls back to the lowercase token', () => {
    const data = { start: 'ab', end: 'ef', chunks: ['abc', 'bcd', 'cde', 'def'], pairs: ['aB'] };
    const result = stitchCharset(data, { charset: P.CHARSETS.alnum, windowSize: 3, tokenLength: 6 });
    assert.deepEqual(result, { token: 'abcdef', length: 6, caseUnresolved: true });
  });
});

test('non-hex payloads still spread their layers over at most three boxes', () => {
  for (const charset of CASED) {
    const { config } = setup(SCENARIOS[0], 3, charset);
    const css = P.generateCSS(config, 'http://frag.test');
    const boxes = css.match(/background:[^;}]*/g).map(b => b.match(/var\(--/g).length);
    assert.ok(boxes.length <= 3, `${charset}: ${boxes.length} boxes`);
    assert.equal(boxes.reduce((a, b) => a + b), P.ruleCount(config) - 2 * P.CHARSETS[charset].fold.length ** 2 + 2);
    for (const n of boxes) assert.ok(n <= 25000, `${n} layers in one box`);
  }
});
