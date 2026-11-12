'use strict';

// A tiny model of a page and of how the browser applies blind-mode rules to
// it, evaluated against the same rule data public/blind.js renders to CSS.
//
// Elements are { tag, attrs, form, rendered }: `form` is the <form> the
// element is a direct child of (or null), `rendered` is whether it gets a box
// (hidden inputs and display:none forms don't). <meta> renders because the
// payload sets head,meta{display:block}.

function el(tag, attrs = {}, { form = null, rendered } = {}) {
  const hidden = tag === 'input' && String(attrs.type).toLowerCase() === 'hidden';
  return { tag, attrs, form, rendered: rendered ?? !hidden };
}

function page(elements) {
  return { html: { tag: 'html', attrs: {}, form: null, rendered: true }, elements };
}

function passes(element, [name, op, value, ci]) {
  let v = element.attrs[name];
  if (v === undefined) return false;
  if (!op) return true;
  let want = value;
  if (ci) {
    v = v.toLowerCase();
    want = want.toLowerCase();
  }
  switch (op) {
    case '=': return v === want;
    case '^=': return want !== '' && v.startsWith(want);
    case '$=': return want !== '' && v.endsWith(want);
    case '*=': return want !== '' && v.includes(want);
    default: throw new Error('unknown op ' + op);
  }
}

function matches(element, m) {
  if (m.tag && element.tag !== m.tag) return false;
  if (!(m.attrs || []).every(t => passes(element, t))) return false;
  if (m.is && m.is.length && !m.is.some(t => passes(element, t))) return false;
  if (m.not && m.not.some(t => passes(element, t))) return false;
  return true;
}

function subjects(doc, scope, match) {
  const hits = doc.elements.filter(e => matches(e, match));
  if (scope === 'self') return hits;
  if (scope === 'form') return [...new Set(hits.map(e => e.form).filter(Boolean))];
  return hits.length ? [doc.html] : [];
}

function isHost(doc, host, element) {
  if (host.scope === 'html') return element === doc.html;
  if (host.scope === 'self') return matches(element, host.match);
  return element.tag === 'form' && doc.elements.some(e => e.form === element && matches(e, host.match));
}

// Every request path the payload would trigger on this page. A custom
// property takes the value of the last matching rule on each element, and is
// only requested if the element renders and lists it in its background (two
// hosts on one element: the later `background` wins).
function requests(doc, payload) {
  const winners = new Map();
  for (const r of payload.rules) {
    for (const s of subjects(doc, r.scope, r.match)) {
      if (!winners.has(s)) winners.set(s, new Map());
      winners.get(s).set(r.prop, r.path);
    }
  }
  const out = new Set();
  for (const [s, props] of winners) {
    if (!s.rendered) continue;
    const hosts = payload.hosts.filter(h => isHost(doc, h, s));
    const listed = new Set(hosts.length ? hosts[hosts.length - 1].props : []);
    for (const [prop, path] of props) if (listed.has(prop)) out.add(path);
  }
  return out;
}

const reconHits = paths =>
  new Set([...paths].filter(p => p.startsWith('r/')).map(p => p.slice(2)));

// Split /b/<id>/... paths into per-field leak data.
function fieldData(paths) {
  const fields = new Map();
  for (const p of paths) {
    const m = p.match(/^b\/(\d+)\/(?:([ser])\/)?([0-9a-f]+)$/);
    if (!m) continue;
    const id = Number(m[1]);
    if (!fields.has(id)) fields.set(id, { s: new Set(), e: new Set(), r: new Set(), m: new Set() });
    fields.get(id)[m[2] || 'm'].add(m[3]);
  }
  const out = new Map();
  for (const [id, f] of fields) {
    out.set(id, { starts: [...f.s], ends: [...f.e], runStarts: [...f.r], chunks: [...f.m] });
  }
  return out;
}

module.exports = { el, page, matches, requests, reconHits, fieldData };
