'use strict';

// Which leaked chunks a payload in a given charset can send, shared by the
// targeted (server.js) and blind (lib/blind-server.js) collectors.
//
// Routes accept any chunk-like path segment (a "/" in a chunk arrives as
// %2F, which Express decodes); validChunk then checks the decoded chunk
// against the active charset, so only what the payload can send is recorded.

const { charsetOf, alphabetOf, isLetter } = require('../public/payload');

// Path-to-regexp pattern for a chunk of min..max chars (each up to 3 raw
// chars when percent-encoded).
const chunkRoute = (min, max) => `[\\w+=%-]{${min},${max * 3}}`;

// t: 'm' window, 's'/'e'/'r' anchor, 'c' case pair.
function validChunk(charset, t, c, length) {
  const cs = typeof charset === 'object' ? charset : charsetOf(charset);
  if (typeof c !== 'string' || c.length !== length) return false;
  if (t === 'c') {
    const alphabet = alphabetOf(cs);
    return cs.cased && [...c].every(ch => alphabet.includes(ch)) && [...c].some(isLetter);
  }
  return [...c].every(ch => cs.fold.includes(ch));
}

module.exports = { chunkRoute, validChunk };
