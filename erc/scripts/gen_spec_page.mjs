#!/usr/bin/env node
// Build-time generator: render the ERC draft markdown into a self-contained,
// styled, standalone HTML spec page for the demo site. Deterministic: same
// source markdown -> byte-identical output. Wired to run before dev/build via
// the `gen:spec` npm script. Writes app/public/spec.html, which the demo SPA
// links to at /spec.html.
//
// Source of truth is the markdown one level ABOVE the erc/ package dir:
//   ../erc-app-layer-private-transfers.md
// The ERCXXXX / ercXXXX placeholders in that file are INTENTIONAL (no assigned
// ERC number yet) and are rendered faithfully, unaltered.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Marked } from "marked";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE_MD = path.resolve(fileURLToPath(import.meta.url), "../../erc-app-layer-private-transfers.md");
const OUT_FILE = path.resolve(HERE, "..", "app", "public", "spec.html");

if (!existsSync(SOURCE_MD)) {
  throw new Error(`spec markdown not found at ${SOURCE_MD}`);
}

// ----------------------------------------------------------------------------
// Read + split off YAML frontmatter (first ---...--- block). Parse the simple
// `key: value` lines ourselves; no yaml dependency needed.
// ----------------------------------------------------------------------------
const raw = readFileSync(SOURCE_MD, "utf8");
const fmMatch = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
if (!fmMatch) throw new Error("could not find leading YAML frontmatter block");

const frontmatter = {};
for (const line of fmMatch[1].split(/\r?\n/)) {
  if (!line.trim()) continue;
  const idx = line.indexOf(":");
  if (idx === -1) continue;
  const key = line.slice(0, idx).trim();
  const value = line.slice(idx + 1).trim();
  frontmatter[key] = value;
}
const body = raw.slice(fmMatch[0].length);

const meta = {
  title: frontmatter.title || "Application-Layer Private ETH and ERC-20 Transfers",
  description: frontmatter.description || "",
  status: frontmatter.status || "Draft",
  type: frontmatter.type || "",
  category: frontmatter.category || "",
  created: frontmatter.created || "",
};

// ----------------------------------------------------------------------------
// Slugs: lowercase, non-alphanumerics -> '-', collapse repeats, trim. Dedupe.
// ----------------------------------------------------------------------------
function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
const usedSlugs = new Map();
function uniqueSlug(text) {
  let base = slugify(text) || "section";
  let slug = base;
  const seen = usedSlugs.get(base) || 0;
  if (seen > 0) slug = `${base}-${seen + 1}`;
  usedSlugs.set(base, seen + 1);
  return slug;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ----------------------------------------------------------------------------
// Lex once. Assign a stable slug to every h2/h3/h4 (attached to the token so
// the renderer and the TOC agree), and build a nested TOC from h2/h3.
// ----------------------------------------------------------------------------
const marked = new Marked({ gfm: true });
const tokens = marked.lexer(body);

const toc = []; // [{ slug, text, children: [{ slug, text }] }]
for (const token of tokens) {
  if (token.type !== "heading" || token.depth < 2 || token.depth > 4) continue;
  const slug = uniqueSlug(token.text);
  token.slug = slug; // consumed by the custom heading renderer below
  if (token.depth === 2) {
    toc.push({ slug, text: token.text, children: [] });
  } else if (token.depth === 3) {
    if (toc.length === 0) toc.push({ slug: "", text: "", children: [] });
    toc[toc.length - 1].children.push({ slug, text: token.text });
  }
}

// Custom renderer: heading ids + anchor links; wrap tables for horizontal scroll.
marked.use({
  renderer: {
    heading(token) {
      const depth = token.depth;
      const inner = this.parser.parseInline(token.tokens);
      const slug = token.slug || uniqueSlug(token.text);
      const anchor =
        depth >= 2 && depth <= 4
          ? `<a class="anchor" href="#${slug}" aria-hidden="true" tabindex="-1">#</a>`
          : "";
      return `<h${depth} id="${slug}">${anchor}${inner}</h${depth}>\n`;
    },
  },
});

let articleHtml = marked.parser(tokens);
// Every table lives in its own overflow-x:auto box so wide tables scroll inside
// themselves and never push the page body sideways.
articleHtml = articleHtml
  .replace(/<table>/g, '<div class="table-wrap"><table>')
  .replace(/<\/table>/g, "</table></div>");

// ----------------------------------------------------------------------------
// TOC markup.
// ----------------------------------------------------------------------------
function renderToc(items) {
  const parts = ['<ul class="toc-list">'];
  for (const item of items) {
    if (!item.slug) continue;
    parts.push(`<li class="toc-h2"><a href="#${item.slug}">${escapeHtml(item.text)}</a>`);
    if (item.children.length) {
      parts.push('<ul class="toc-sub">');
      for (const child of item.children) {
        parts.push(`<li class="toc-h3"><a href="#${child.slug}">${escapeHtml(child.text)}</a></li>`);
      }
      parts.push("</ul>");
    }
    parts.push("</li>");
  }
  parts.push("</ul>");
  return parts.join("\n");
}
const tocHtml = renderToc(toc);

// ----------------------------------------------------------------------------
// Status chips from frontmatter (honest, factual).
// ----------------------------------------------------------------------------
const chips = [
  meta.status ? meta.status.toUpperCase() : null,
  meta.type || null,
  meta.category || null,
  meta.created ? `created ${meta.created}` : null,
]
  .filter(Boolean)
  .map((c) => `<span class="chip">${escapeHtml(c)}</span>`)
  .join('<span class="chip-sep">·</span>');

const headingCount = (articleHtml.match(/<h[234] id=/g) || []).length;

// ----------------------------------------------------------------------------
// Assemble the standalone document. All CSS inlined; no dependency on the app
// stylesheet. Fonts loaded from the same Google Fonts URL the app uses.
// ----------------------------------------------------------------------------
const css = `
:root {
  --bg:#08090a; --bg-1:#0b0d0e; --panel:#0d0f11; --panel-2:#101416;
  --hair:rgba(180,220,205,0.09); --hair-strong:rgba(180,220,205,0.16);
  --ink:#e9ede9; --ink-dim:#b6bfba; --muted:#727b76; --muted-2:#565e59;
  --accent:#7cffcb; --accent-dim:rgba(124,255,203,0.13); --accent-glow:rgba(124,255,203,0.34);
  --exposed:#f0e6d2;
  --serif:"Fraunces",Georgia,serif;
  --mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;
}
* { box-sizing:border-box; }
html, body { margin:0; padding:0; }
html { scroll-behavior:smooth; }
body {
  background:var(--bg); color:var(--ink); font-family:var(--serif);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
  overflow-x:hidden; line-height:1.7;
}
.vignette {
  position:fixed; inset:0; z-index:0; pointer-events:none;
  background:
    radial-gradient(120% 90% at 50% -10%, rgba(124,255,203,0.06), transparent 60%),
    radial-gradient(100% 100% at 50% 120%, rgba(0,0,0,0.6), transparent 55%);
}
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }

/* ---- top bar ---- */
.topbar {
  position:sticky; top:0; z-index:30;
  display:flex; align-items:center; justify-content:space-between; gap:16px;
  padding:14px clamp(16px,4vw,40px);
  border-bottom:1px solid var(--hair);
  background:rgba(8,9,10,0.72); backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px);
}
.brand { display:inline-flex; align-items:center; gap:11px; color:var(--ink); text-decoration:none; }
.brand:hover { text-decoration:none; }
.brand-mark { position:relative; width:20px; height:20px; display:inline-block; flex:none; }
.brand-ring { position:absolute; inset:0; border:1.5px solid var(--accent); border-radius:50%; opacity:0.85; box-shadow:0 0 14px var(--accent-glow); }
.brand-dot { position:absolute; inset:6px; background:var(--accent); border-radius:50%; box-shadow:0 0 10px var(--accent-glow); }
.brand-text { font-family:var(--serif); font-weight:600; font-size:17px; letter-spacing:-0.01em; }
.brand-accent { color:var(--accent); }
.brand-sub {
  font-family:var(--mono); font-size:10px; letter-spacing:0.18em; text-transform:uppercase;
  color:var(--muted); border-left:1px solid var(--hair-strong); padding-left:12px; margin-left:2px;
}
.back {
  font-family:var(--mono); font-size:12px; letter-spacing:0.03em; color:var(--ink-dim);
  border:1px solid var(--hair-strong); padding:7px 12px; border-radius:2px; white-space:nowrap;
  background:rgba(255,255,255,0.015); transition:color 0.2s, border-color 0.2s, background 0.2s;
}
.back:hover { color:var(--accent); border-color:var(--accent-glow); background:var(--accent-dim); text-decoration:none; }

/* ---- banner ---- */
.banner {
  position:relative; z-index:2;
  max-width:1120px; margin:0 auto; padding:clamp(36px,6vw,72px) clamp(18px,4vw,40px) clamp(20px,3vw,36px);
  border-bottom:1px solid var(--hair);
}
.banner .chips {
  display:flex; align-items:center; flex-wrap:wrap; gap:9px;
  font-family:var(--mono); font-size:11px; letter-spacing:0.14em; text-transform:uppercase;
  color:var(--muted); margin-bottom:22px;
}
.chip { color:var(--accent); }
.chip-sep { color:var(--muted-2); }
.spec-title {
  font-family:var(--serif); font-weight:600; letter-spacing:-0.02em; line-height:1.05;
  font-size:clamp(30px,5vw,50px); margin:0 0 18px; color:var(--ink); max-width:20ch;
}
.spec-desc { font-size:clamp(15px,2vw,18px); line-height:1.6; color:var(--ink-dim); max-width:64ch; margin:0 0 22px; }
.draft-note {
  font-family:var(--mono); font-size:12px; line-height:1.65; color:var(--muted);
  max-width:70ch; margin:0; padding:12px 16px;
  border:1px solid var(--hair); border-left:2px solid var(--accent-glow);
  border-radius:2px; background:rgba(124,255,203,0.03);
}
.draft-note strong { color:var(--ink-dim); font-weight:500; }

/* ---- two-column layout ---- */
.layout {
  position:relative; z-index:2;
  max-width:1120px; margin:0 auto; padding:0 clamp(18px,4vw,40px);
  display:grid; grid-template-columns:230px minmax(0,1fr); gap:clamp(28px,4vw,56px);
  align-items:start;
}
.toc {
  position:sticky; top:70px; align-self:start;
  max-height:calc(100vh - 90px); overflow-y:auto;
  padding:28px 8px 40px 0; font-family:var(--mono);
}
.toc-title {
  font-size:10px; letter-spacing:0.22em; text-transform:uppercase; color:var(--muted-2); margin:0 0 14px;
}
.toc-list, .toc-sub { list-style:none; margin:0; padding:0; }
.toc-list > li { margin:0 0 3px; }
.toc-sub { margin:2px 0 8px 0; padding-left:12px; border-left:1px solid var(--hair); }
.toc a {
  display:block; color:var(--muted); text-decoration:none;
  font-size:12px; line-height:1.4; padding:4px 6px; border-radius:2px;
  transition:color 0.15s, background 0.15s;
}
.toc-h2 > a { color:var(--ink-dim); font-size:12.5px; }
.toc-h3 > a { color:var(--muted); font-size:11.5px; }
.toc a:hover { color:var(--accent); background:var(--accent-dim); text-decoration:none; }

/* ---- article ---- */
.spec-body {
  min-width:0; max-width:760px; padding:28px 0 120px;
  color:var(--ink-dim); font-size:16.5px; line-height:1.75;
}
.spec-body > *:first-child { margin-top:0; }
.spec-body h2, .spec-body h3, .spec-body h4 {
  font-family:var(--serif); color:var(--ink); letter-spacing:-0.01em;
  scroll-margin-top:80px; position:relative;
}
.spec-body h2 {
  font-size:clamp(24px,3.4vw,32px); font-weight:600; line-height:1.15;
  margin:2.4em 0 0.7em; padding-bottom:0.35em; border-bottom:1px solid var(--hair);
}
.spec-body h3 { font-size:clamp(19px,2.5vw,23px); font-weight:600; margin:2em 0 0.6em; }
.spec-body h4 { font-size:17px; font-weight:600; margin:1.7em 0 0.5em; color:var(--ink-dim); }
.spec-body h2:first-child, .spec-body h3:first-child { margin-top:0; }
.anchor {
  position:absolute; left:-0.9em; top:0; width:0.9em;
  color:var(--muted-2); text-decoration:none; opacity:0; font-weight:400;
  transition:opacity 0.15s;
}
.spec-body h2:hover .anchor,
.spec-body h3:hover .anchor,
.spec-body h4:hover .anchor { opacity:1; }
.anchor:hover { color:var(--accent); text-decoration:none; }

.spec-body p { margin:0 0 1.15em; }
.spec-body a { color:var(--accent); text-decoration:none; }
.spec-body a:hover { text-decoration:underline; }
.spec-body strong { color:var(--ink); font-weight:600; }
.spec-body em { color:var(--exposed); font-style:italic; }

.spec-body ul, .spec-body ol { margin:0 0 1.2em; padding-left:1.5em; }
.spec-body li { margin:0.3em 0; }
.spec-body li::marker { color:var(--muted); }

/* inline code + hex strings */
.spec-body code {
  font-family:var(--mono); font-size:0.84em; color:var(--accent);
  background:var(--accent-dim); padding:0.08em 0.35em; border-radius:2px;
  word-break:break-word; overflow-wrap:anywhere;
}
/* fenced code blocks */
.spec-body pre {
  margin:0 0 1.4em; padding:16px 18px; overflow-x:auto;
  background:var(--panel-2); border:1px solid var(--hair); border-radius:3px;
  font-family:var(--mono); font-size:13px; line-height:1.6;
}
.spec-body pre code {
  color:var(--ink-dim); background:none; padding:0; border-radius:0;
  font-size:inherit; white-space:pre; word-break:normal; overflow-wrap:normal;
}

/* blockquotes */
.spec-body blockquote {
  margin:0 0 1.3em; padding:0.2em 0 0.2em 1.1em;
  border-left:2px solid var(--accent-glow); color:var(--muted);
}
.spec-body blockquote p:last-child { margin-bottom:0; }

.spec-body hr { border:none; border-top:1px solid var(--hair); margin:2.4em 0; }

/* tables — each in its own overflow-x:auto box */
.table-wrap {
  overflow-x:auto; margin:0 0 1.5em;
  border:1px solid var(--hair); border-radius:3px;
}
.spec-body table {
  border-collapse:collapse; width:100%;
  font-family:var(--mono); font-size:12.5px; line-height:1.5;
}
.spec-body th, .spec-body td {
  padding:8px 12px; text-align:left; vertical-align:top;
  border-bottom:1px solid var(--hair); border-right:1px solid var(--hair);
  white-space:nowrap;
}
.spec-body th:last-child, .spec-body td:last-child { border-right:none; }
.spec-body tr:last-child td { border-bottom:none; }
.spec-body thead th { background:var(--panel-2); color:var(--ink); font-weight:600; }
.spec-body tbody tr:hover td { background:rgba(255,255,255,0.015); }
.spec-body td code, .spec-body th code { white-space:nowrap; }

/* ---- responsive: single column below 900px ---- */
@media (max-width:900px) {
  .layout { grid-template-columns:1fr; gap:0; }
  .toc {
    position:static; max-height:none; overflow:visible;
    padding:24px 0 8px; margin-bottom:8px; border-bottom:1px solid var(--hair);
  }
  .toc-sub { display:none; }
  .spec-body { padding-top:24px; }
  .anchor { display:none; }
}
`.trim();

const draftNote = `<strong>Draft proposal.</strong> This document is an unofficial draft published for the accompanying demo. It has <strong>not</strong> been assigned an EIP/ERC number and is not part of any official standards track; the <code>ERCXXXX</code> / <code>ercXXXX</code> placeholders throughout are intentional. Rendered verbatim from the source markdown.`;

const html = `<!-- GENERATED by scripts/gen_spec_page.mjs — do not edit by hand.
     Source: erc-app-layer-private-transfers.md. Regenerate with: npm run gen:spec -->
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>${escapeHtml(meta.title)} — Draft Spec</title>
<meta name="description" content="${escapeHtml(meta.description)}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%2308090a'/%3E%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%237CFFCB' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='2.4' fill='%237CFFCB'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600;9..144,700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
${css}
</style>
</head>
<body>
<div class="vignette"></div>
<header class="topbar">
  <a class="brand" href="/">
    <span class="brand-mark"><span class="brand-ring"></span><span class="brand-dot"></span></span>
    <span class="brand-text">Shielded<span class="brand-accent">Terminal</span></span>
    <span class="brand-sub">Draft Spec</span>
  </a>
  <a class="back" href="/">&larr; Back to demo</a>
</header>

<div class="banner">
  <div class="chips">${chips}</div>
  <h1 class="spec-title">${escapeHtml(meta.title)}</h1>
  <p class="spec-desc">${escapeHtml(meta.description)}</p>
  <p class="draft-note">${draftNote}</p>
</div>

<div class="layout">
  <nav class="toc" aria-label="Table of contents">
    <p class="toc-title">Contents</p>
    ${tocHtml}
  </nav>
  <article class="spec-body">
${articleHtml}
  </article>
</div>
</body>
</html>
`;

writeFileSync(OUT_FILE, html, "utf8");
console.log(`gen:spec -> ${path.relative(path.resolve(HERE, ".."), OUT_FILE)}`);
console.log(`  source: ${path.basename(SOURCE_MD)}  (${raw.length} bytes)`);
console.log(`  headings with ids: ${headingCount}  |  toc entries: ${toc.filter((t) => t.slug).length} h2`);
console.log(`  output: ${html.length} bytes`);
