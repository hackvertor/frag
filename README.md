<p align="center">
  <img src="graphics/frag.png" alt="frag" width="500">
</p>

<p align="center"><em>CSS token exfiltration tool</em></p>

## What is Frag?

Frag is a tool for extracting secret tokens from web pages using only CSS — no JavaScript required. It generates CSS payloads that use attribute selectors and `background-image` URLs to exfiltrate overlapping token fragments to an attacker-controlled server, then reconstructs the full token using De Bruijn graph traversal and Eulerian path algorithms.

This is useful in contexts where CSS injection is possible but JavaScript is blocked — such as webmail clients, HTML email rendering, or pages with strict Content Security Policies.

**Note:** Frag currently only supports hex-based tokens (characters `0-9`, `a-f`).

## How it works

1. **Fragment exfiltration** — For every possible hex window of 3 or 4 characters, a CSS attribute selector (`*=`) fires a `background-image` request to your server if the token's attribute contains it. Two small rule sets (`^=`/`$=`, or `*=` with the known surrounding text) leak the token's first and last two characters.

2. **Reconstruction** — Frag builds the token one character at a time, keeping only tokens of the configured length that match the leaked start and end and contain nothing but leaked windows.

3. **Noise handling** — Hex from the rest of the attribute (e.g. `bac` in `callback`, or junk query parameters) also leaks and can link into the token. Candidates are ranked by how cheaply the windows they leave unused can be explained as one contiguous run of junk, so junk is left over rather than spliced into the token.

4. **Ambiguity reporting** — Only the *set* of windows leaks, not their order or count, so different tokens can leak identical data. When that happens every equally plausible token is listed as a candidate rather than one being picked at random.

### Window size

The window size trades CSS size against accuracy. Measured on random hex tokens in an anchor href followed by random hex junk:

| Window | CSS | Single correct guess, 12 chars | 24 chars | 40 chars | 64 chars |
|---|---|---|---|---|---|
| 4 chars (default) | ~4.5 MB | 100% | 100% | 99.5% | ~97% |
| 3 chars | ~300 KB | ~97% | ~72% | ~28% | ~1% |

With 3-char windows the real token is still in the candidate list ~98% of the time at 40 chars; it just isn't the only answer. CSS size also grows with the length of your server's origin, since it appears in every rule.

Chrome crashes the tab when a single element has tens of thousands of background layers (65k crashed, 32k was fine), so the 4-char payload spreads its layers across the element and its `::before`/`::after`. This has two side effects on the target page: any existing `::before`/`::after` content on that element is replaced, and if the page's own styles win the cascade for those pseudo-elements' `background`, the windows assigned to them won't leak and extraction fails. The 3-char payload uses only the element itself.

The server treats a quiet gap of one second as the boundary between extractions: it waits for that gap before stitching, so a poll mid-burst can't lock in a reconstruction from partial data, and the first request after a gap starts a fresh extraction.

## Features

- Web UI for configuration, payload generation, and live token display
- Support for anchor elements (`<a href="...">`) and hidden inputs (`<input type="hidden">`)
- Two copy modes: HTML (for pasting into contenteditable test pages) and plain text (for exploitation)
- Sample token with test HTML for verifying payloads in-browser
- Automatic stitching once a burst of requests has finished

## Getting started

```bash
npm install
node server.js
```

Then visit `http://localhost:3000` in your browser.

### Configuration

Use the web UI to configure:

| Field | Description |
|-------|-------------|
| **type** | Element type — Anchor or Hidden Input |
| **selector** | CSS selector matching the target element |
| **attr** | Attribute containing the token |
| **name** | Display name for the token |
| **start** | Known text immediately before the token |
| **end** | Known text immediately after the token |
| **length** | Expected token length |
| **window** | 4 chars (~99% accurate, ~4.5 MB) or 3 chars (~300 KB, longer tokens may give candidates) |

### Testing

```bash
npm test
```

The tests generate random hex tokens of every length from 6 to 40, embed them in anchors (with and without random hex junk on the end of the href) and hidden inputs, work out which requests the real CSS payload (`public/payload.js`) would trigger, and check the stitched result. Runs are seeded; use `FRAG_SEED=<n> npm test` to try a different set of tokens.

### Usage

1. Configure the target element and token parameters
2. Click **Apply** to update the server
3. Copy the generated CSS payload
4. Inject the CSS into the target page
5. Watch the token appear in the terminal as chunks arrive

## Background

The original concept for CSS-only token exfiltration was developed by [Gareth Heyes](https://portswigger.net/research/css-the-bomb-inside-your-inbox), demonstrating how CSS attribute selectors and background image requests could be weaponised to steal tokens from webmail clients — without any JavaScript. The initial technique worked for short tokens but required very large stylesheets (~258 MB for a 12-character hex token).

[Alex Craig](https://portswigger.net/research/smashing-the-token-limit) dramatically improved the technique by reframing extraction as overlap-based reconstruction using graph theory. By using overlapping fragment chunks instead of brute-forcing individual characters, Alex reduced the CSS size by over 1,000x for 12-character tokens (down to ~1.33 MB at 99% success rate) and scaled the approach to extract tokens of 210+ hex characters within the original byte budget.

## Credits

- **Gareth Heyes** — Original concept, initial research ([CSS: the bomb inside your inbox](https://portswigger.net/research/css-the-bomb-inside-your-inbox)), and tool author
- **Alex Craig** — Overlap-based reconstruction technique, validation framework, and scalability improvements ([Smashing the token limit](https://portswigger.net/research/smashing-the-token-limit))
