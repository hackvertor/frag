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

## Blind mode

Blind mode extracts tokens from a page you don't have selectors for. It only uses `background-image` requests, so it works where `@import` is blocked. Without `@import` there's no recursion: each injection is one static stylesheet. So blind mode runs in two stages.

1. **Recon** (~200 KB). Wordlist probes report:
   - which fields exist: hidden/other inputs by `name`, `<meta name>`, `?name=` params in `a[href]` and `form[action]`, and `data-*` attributes
   - which element can host the extraction requests
   - whether each value is lowercase hex

   CSS can't enumerate attribute names or read values, so names can only come from the wordlists in `public/blind.js`. A hidden input whose name isn't listed is flagged but can't be extracted.

2. **Extract**. Pick fields from the recon results and frag builds a payload for them. It's like targeted mode, but every URL is namespaced by field (`/b/<id>/abcd`). That's because the browser only loads an identical URL once, so windows from different fields would otherwise be indistinguishable. The token length isn't known, so the solver tries a range of lengths:
   - **Whole values** (input, meta, data-\*): the shortest token that uses every leaked window.
   - **URL params**: candidates are ranked by how many characters they need for the token plus the junk around it. These payloads also leak where each param value starts (`=ab`) and every possible end (`ab&`, `ab#`, end of URL). Leftovers that start or end mid-value then count against a candidate.

Usage: switch the UI to **blind**, copy the recon payload, inject it, then pick the discovered fields, copy the extract payload and inject that. The test area has a sample page with one field of each kind.

### Hosts

Hidden inputs and `<meta>` don't render, so their requests need another element:

| Field | Host | Notes |
|---|---|---|
| input in a rendered form | `form:has(>input[name=… i][value*=…])` | Fast (~0.1 s for 65k rules) |
| other inputs | `html:has(input[…])` | Cost grows with page size (~3 s for 4-char windows on a 3,000-element page) |
| meta | the meta itself, with `head,meta{display:block}` | |
| `a`/`form` params, `data-*` | the element itself | |

Recon checks the form host by firing its probe *from* the form, so a `display:none` form isn't used. Each kind of host is one element plus its `::before`/`::after`. That holds one 4-char field or about 16 3-char fields. When a kind is full, inputs and data attributes fall back to `html`, and if nothing fits frag asks you to use 3-char windows or a separate pass. Hosts replace the background, and `::before`/`::after`, of the elements they're on.

### Accuracy and size

Measured with random hex tokens and unknown length (`test/blind.test.js`). The URL-param case has random hex junk params before and after the token.

| Field | Window | CSS per field | Single correct guess | Token listed |
|---|---|---|---|---|
| input / meta / data | 4 chars | ~6–7 MB | ~95% (6–64 chars) | 100% |
| input / meta / data | 3 chars | ~0.4–0.5 MB | ~60% (6–40 chars) | ~99% |
| URL param with junk | 4 chars | ~6 MB | ~70% (8–64 chars) | 100% |
| URL param with junk | 3 chars | ~0.5 MB | rare | ~85% (8–24 chars) |

A whole value that repeats a substring (e.g. `fffff`) leaks the same windows as one with fewer repeats, so every length that fits is listed, shortest first. URL params are ambiguous more often because a chance overlap can let the token's tail swap with a junk param's. Both splits then fit the leaked data equally well, so both are listed.

### Chrome behaviour this relies on

- A stylesheet with more than 2^18 (262,144) rules is silently ignored, so payloads with several 4-char fields are split over multiple `<style>` elements.
- Chrome takes ~7 s to build a sheet with tens of thousands of top-level attribute selectors such as `a[href*="abcd"]`, even if none match. Wrapped in `:is()` (`a:is([href*="abcd"])`), the same rules take ~0.1 s, so blind payloads keep their attribute tests inside `:is()`. The targeted payload doesn't do this yet.
- Sibling hosts (`input[…] ~ *`) put every rule in Chrome's universal bucket and hung the tab on a 3,000-element page. Blind mode doesn't use them.

## Features

- Web UI for configuration, payload generation, and live token display
- Support for anchor elements (`<a href="...">`) and hidden inputs (`<input type="hidden">`)
- Two copy modes: HTML (for pasting into contenteditable test pages) and plain text (for exploitation)
- Sample token with test HTML for verifying payloads in-browser
- Automatic stitching once a burst of requests has finished
- Blind mode: discovers fields from wordlists and extracts tokens of unknown length without selectors

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

The tests generate random hex tokens of every length from 6 to 40, embed them in anchors (with and without random hex junk on the end of the href) and hidden inputs, work out which requests the real CSS payload (`public/payload.js`) would trigger, and check the stitched result. `test/blind.test.js` does the same for blind mode. It evaluates the recon and extract rules against a small model of a page (`test/blind-helpers.js`), from the same rule data the CSS is rendered from. Runs are seeded; use `FRAG_SEED=<n> npm test` to try a different set of tokens.

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
