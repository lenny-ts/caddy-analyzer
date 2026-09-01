#!/usr/bin/env node
/* Build docs/search-index.json from built HTML pages.
   v2: dynamic scan of all docs HTML (not hardcoded).
   Each entry = { page, href, title, kind, body }.
   Consumed by docs.js for search. */
const fs = require("fs");
const path = require("path");

const docsDir = path.join(__dirname, "..", "docs");

function collectPages() {
  const pages = [];
  function walk(dir, rel) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      const r = rel ? rel + "/" + e.name : e.name;
      if (e.isDirectory()) {
        if (e.name === "src") continue;
        walk(p, r);
      } else if (e.name.endsWith(".html")) {
        if (e.name === "404.html" || e.name.startsWith("_")) continue;
        if (r === "demo.html") continue;
        if (r === "subcommands.html") continue; // legacy monolithic, superseded by reference/cli.html
        pages.push(r);
      }
    }
  }
  walk(docsDir, "");
  return pages.sort();
}

const pageTitle = (rel, raw) => {
  const htmlTitle = raw.match(/<title>([^<]+)<\/title>/i);
  if (htmlTitle) return htmlTitle[1].replace(/\s+[—-]\s+caddy-analyzer$/, "");
  const map = {
    "index.html": "Overview",
    "quickstart.html": "Quickstart",
    "installation.html": "Installation",
    "sources.html": "Log Sources",
    "security.html": "Threat Engine",
    "architecture.html": "Architecture",
    "contributing.html": "Contributing",
    "faq.html": "FAQ",
    "changelog.html": "Changelog",
    "tui-html.html": "TUI & HTML Reports",
    "404.html": "Not Found",
    "guide/configuration.html": "Configuration",
    "guide/usage.html": "Usage",
    "guide/examples.html": "Examples",
    "guide/troubleshooting.html": "Troubleshooting",
    "reference/cli.html": "CLI Reference",
    "reference/commands.html": "All commands",
    "reference/api.html": "API / Packages",
    "reference/security-categories.html": "26 Categories",
    "reference/security-detection.html": "MITRE, Sigma & Evasion",
    "subcommands-guard.html": "guard",
    "subcommands-blocklist.html": "blocklist",
    "subcommands-block.html": "block / unban",
    "subcommands-top.html": "top",
  };
  return map[rel] || rel.replace(/\.html$/, "").replace(/\//g, " / ");
};

const slugify = (text) =>
  text.toLowerCase().replace(/[^\w\s-]/g, "").replace(/\s+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");

const textOf = (html) =>
  html.replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();

const PAGES = collectPages();
const entries = [];

for (const file of PAGES) {
  const raw = fs.readFileSync(path.join(docsDir, file), "utf8");
  const title = pageTitle(file, raw);
  entries.push({ page: title, href: file, title, kind: "Page", body: "" });

  const mainMatch = raw.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
  const main = mainMatch ? mainMatch[1] : raw;

  const headingRe = /<h([23])[^>]*>([\s\S]*?)<\/h\1>/gi;
  const headings = [];
  let m;
  while ((m = headingRe.exec(main)) !== null) {
    const inner = m[2].replace(/<a class="heading-anchor"[\s\S]*?<\/a>/g, "").trim();
    headings.push({ level: Number(m[1]), title: textOf(inner), start: m.index + m[0].length });
  }

  headings.forEach((h, i) => {
    const end = i + 1 < headings.length ? headings[i + 1].start : main.length;
    const body = textOf(main.slice(h.start, end)).replace(new RegExp("^" + h.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "");
    entries.push({ page: title, href: file + "#" + slugify(h.title), title: h.title, kind: h.level === 2 ? "Section" : "Subsection", body: body.slice(0, 800) });
  });
}

fs.writeFileSync(path.join(docsDir, "search-index.json"), JSON.stringify({ version: 1, entries }));
console.log("search-index.json:", entries.length, "entries,", fs.statSync(path.join(docsDir, "search-index.json")).size, "bytes", `(${PAGES.length} pages)`);
console.log(" pages:", PAGES.join(", "));
