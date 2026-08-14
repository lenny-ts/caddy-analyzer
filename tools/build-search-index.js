#!/usr/bin/env node
/* Build docs/search-index.json from the static HTML pages.
   Each entry = { page, href, title, kind, body } where body is the plain-text
   content of a page section (h2/h3 with following paragraphs/pre blocks).
   Consumed by the command palette for cross-page full-text search.
   Run via tools/minify.sh (or standalone: node tools/build-search-index.js). */

const fs = require("fs");
const path = require("path");

const docsDir = path.join(__dirname, "..", "docs");
const PAGES = [
  "index.html",
  "installation.html",
  "sources.html",
  "subcommands.html",
  "security.html",
  "tui-html.html",
];

const pageTitle = (file) => {
  const meta = {
    "index.html": "Overview",
    "installation.html": "Installation",
    "sources.html": "Log Sources",
    "subcommands.html": "Subcommands",
    "security.html": "Security Threats",
    "tui-html.html": "TUI & HTML Reports",
  };
  return meta[file] || file.replace(/\.html$/, "");
};

const slugify = (text) =>
  text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

const textOf = (html) =>
  html
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const entries = [];

for (const file of PAGES) {
  const raw = fs.readFileSync(path.join(docsDir, file), "utf8");
  const title = pageTitle(file);
  entries.push({ page: title, href: file, title, kind: "Page", body: "" });

  const mainMatch = raw.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
  const main = mainMatch ? mainMatch[1] : raw;

  const headingRe = /<h([23])[^>]*>([\s\S]*?)<\/h\1>/gi;
  const headings = [];
  let m;
  while ((m = headingRe.exec(main)) !== null) {
    headings.push({
      level: Number(m[1]),
      title: textOf(m[2]),
      start: m.index + m[0].length,
    });
  }

  headings.forEach((h, i) => {
    const end = i + 1 < headings.length ? headings[i + 1].start : main.length;
    const body = textOf(main.slice(h.start, end)).replace(
      new RegExp("^" + h.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      ""
    );
    entries.push({
      page: title,
      href: file + "#" + slugify(h.title),
      title: h.title,
      kind: h.level === 2 ? "Section" : "Subsection",
      body: body.slice(0, 800),
    });
  });
}

fs.writeFileSync(
  path.join(docsDir, "search-index.json"),
  JSON.stringify({ version: 1, entries })
);
console.log(
  "search-index.json:",
  entries.length,
  "entries,",
  fs.statSync(path.join(docsDir, "search-index.json")).size,
  "bytes"
);