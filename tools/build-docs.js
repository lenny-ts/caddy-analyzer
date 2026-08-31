#!/usr/bin/env node
// Build step: injects header/sidebar/footer/TOC into docs/*.html
// Zero deps — Node stdlib only. Handles future docs/it/* with same layout.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'docs', 'src');
const OUT = path.join(ROOT, 'docs');
const SITE = 'https://lenny-ts.github.io/caddy-analyzer';
// Add a language here and create its index page to make it available in the UI.
const LANGUAGES = [
  { code: 'en', label: 'EN', root: '', ui: { primary: 'Primary', language: 'Language', sidebar: 'Page navigation', documentation: 'Documentation', overview: 'Overview', quickstart: 'Quickstart', installation: 'Installation', sources: 'Log Sources', guide: 'Guide', configuration: 'Configuration', usage: 'Usage', examples: 'Examples', troubleshooting: 'Troubleshooting', reference: 'Reference', cli: 'CLI Reference', categories: '— Categories', detection: '— Detection', guard: '— Guard', blocklist: '— Blocklist', block: '— Block / Unban', top: '— Top', api: 'API / Packages', threat: 'Threat Engine', architecture: 'Architecture', tui: 'TUI & HTML Reports', contributing: 'Contributing', faq: 'FAQ', changelog: 'Changelog', onPage: 'On this page', updated: 'updated', openSource: 'is open-source under' } },
  { code: 'it', label: 'IT', root: 'it', ui: { primary: 'Navigazione principale', language: 'Lingua', sidebar: 'Navigazione della pagina', documentation: 'Documentazione', overview: 'Panoramica', quickstart: 'Avvio rapido', installation: 'Installazione', sources: 'Sorgenti log', guide: 'Guida', configuration: 'Configurazione', usage: 'Utilizzo', examples: 'Esempi', troubleshooting: 'Risoluzione problemi', reference: 'Riferimento', cli: 'Riferimento CLI', categories: '— Categorie', detection: '— Rilevamento', guard: '— Guard', blocklist: '— Blocklist', block: '— Block / Unban', top: '— Top', api: 'API / Pacchetti', threat: 'Motore minacce', architecture: 'Architettura', tui: 'Report TUI e HTML', contributing: 'Contribuire', faq: 'FAQ', changelog: 'Registro modifiche', onPage: 'In questa pagina', updated: 'aggiornata', openSource: 'è open-source sotto licenza' } },
];
function read(p) { return fs.readFileSync(p, 'utf8'); }
function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }

function loadPartials() {
  const h = read(path.join(SRC, '_partials', 'header.html'));
  const s = read(path.join(SRC, '_partials', 'sidebar.html'));
  const f = read(path.join(SRC, '_partials', 'footer.html'));
  const layout = read(path.join(SRC, 'layout.html'));
  return { header: h, sidebar: s, footer: f, layout };
}

function extractHeadings(html) {
  const headings = [];
  const re = /<h([23])\b[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    // also catch h2/h3 without id — will be slugified in docs.js, but for TOC we only list those with id or generate one
    const level = m[1];
    const id = m[2];
    const text = m[3].replace(/<[^>]+>/g, '').replace(/#$/, '').trim();
    if (headingShouldSkip(m[0])) continue;
    headings.push({ level, id, text });
  }
  // fallback: h2/h3 without id
  const re2 = /<h([23])\b(?![^>]*\bid=)[^>]*>([\s\S]*?)<\/h\1>/gi;
  while ((m = re2.exec(html)) !== null) {
    if (headingShouldSkip(m[0])) continue;
    const level = m[1];
    const raw = m[2].replace(/<[^>]+>/g, '').trim();
    const id = slugify(raw);
    if (!id) continue;
    headings.push({ level, id, text: raw });
  }
  return headings;
}

function headingShouldSkip(tag) {
  // skip headings inside table/pre/callout — handled by placeholder check in docs.js, here approximate
  return false;
}

function slugify(s) {
  return s.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}

function buildToc(headings, ui) {
  if (!headings.length) return ''; // optional — no box if no h2/h3
  let html = `<nav class="doc-toc" aria-label="${ui.onPage}"><div class="toc-label">${ui.onPage}</div>`;
  for (const h of headings) {
    const cls = h.level === '3' ? ' toc-link h3' : ' toc-link';
    html += `<a href="#${h.id}" class="${cls.trim()}">${escapeHtml(h.text)}</a>`;
  }
  html += '</nav>';
  return html;
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function breadcrumbHtml(breadcrumb) {
  if (!breadcrumb) return '';
  // breadcrumb: [{label, href}, ...] last is current
  let html = '<nav class="breadcrumb" aria-label="Breadcrumb">';
  for (let i = 0; i < breadcrumb.length; i++) {
    const b = breadcrumb[i];
    if (i > 0) html += '<span class="sep">/</span>';
    if (b.href && i < breadcrumb.length - 1) html += `<a href="${b.href}">${b.label}</a>`;
    else html += `<span>${b.label}</span>`;
  }
  html += '</nav>';
  return html;
}

function pageMetaHtml(date, ui) {
  // date from git or fallback
  const d = date || new Date().toISOString().slice(0, 10);
  return `<div class="page-meta"><a href="https://github.com/lenny-ts/caddy-analyzer/releases">v0.6.1</a> · ${ui.updated} <time datetime="${d}">${d}</time> · <a href="https://github.com/lenny-ts/caddy-analyzer">GitHub</a></div>`;
}

function hreflangTags(outRel, lang) {
  // outRel: e.g. "index.html" or "guide/configuration.html" or "it/index.html"
  const isIt = outRel.startsWith('it/');
  const enRel = isIt ? outRel.slice(3) : outRel;
  const itRel = isIt ? outRel : 'it/' + outRel;
  const enHref = `${SITE}/${enRel}`;
  const itHref = `${SITE}/${itRel}`;
  const itExists = exists(path.join(OUT, itRel));
  const enExists = exists(path.join(SRC, enRel)) || exists(path.join(OUT, enRel));

  let tags = '';
  // x-default always EN
  tags += `<link rel="alternate" hreflang="x-default" href="${enHref}">\n`;
  tags += `  <link rel="alternate" hreflang="en" href="${enHref}">`;
  if (itExists) {
    tags += `\n  <link rel="alternate" hreflang="it" href="${itHref}">`;
  }
  // canonical
  const selfHref = lang === 'it' ? itHref : enHref;
  return { tags, canonical: `<link rel="canonical" href="${selfHref}">` };
}

function langSwitcher(outRel, lang) {
  const current = LANGUAGES.find((item) => item.code === lang) || LANGUAGES[0];
  const currentDir = path.posix.dirname(outRel);
  const localizedPath = (language, page) => language.root ? `${language.root}/${page}` : page;
  const hrefFor = (target) => path.posix.relative(currentDir, target) || path.posix.basename(target);
  const options = LANGUAGES.map((target) => {
    if (target.code === current.code) {
      return `<span class="lang-option active" aria-current="page">${target.label}</span>`;
    }
    const exact = localizedPath(target, current.root ? outRel.slice(current.root.length + 1) : outRel);
    const targetPath = exists(path.join(SRC, exact)) || exists(path.join(OUT, exact))
      ? exact
      : localizedPath(target, 'index.html');
    const available = exists(path.join(SRC, targetPath)) || exists(path.join(OUT, targetPath));
    if (!available) return `<span class="lang-option disabled" title="${target.label} translation coming soon" aria-disabled="true">${target.label}</span>`;
    const fallback = targetPath !== exact;
    const title = fallback ? ` title="${target.label} translation in progress"` : '';
    return `<a class="lang-option" href="${hrefFor(targetPath)}" hreflang="${target.code}" lang="${target.code}"${title}>${target.label}</a>`;
  }).join('');
  return `<div class="language-switch" role="group" aria-label="${current.ui.language}">${options}</div>`;
}

function buildPage(srcPath, partials) {
  const srcRel = path.relative(SRC, srcPath); // e.g. index.html or guide/configuration.html or it/index.html
  const isIt = srcRel.startsWith('it' + path.sep) || srcRel.startsWith('it/');
  const lang = isIt ? 'it' : 'en';
  const language = LANGUAGES.find((item) => item.code === lang) || LANGUAGES[0];
  const ui = language.ui;
  const outRel = srcRel; // mirror
  const outPath = path.join(OUT, outRel);

  let raw = read(srcPath);
  // Frontmatter: <!-- fm: title=... | description=... | breadcrumb=... | date=... -->
  // Format: first line <!-- fm: key=value | key=value -->
  let fm = { title: 'caddy-analyzer', description: '', breadcrumb: null, date: null, bodyClass: '' };
  const fmMatch = raw.match(/^<!--\s*fm:\s*([\s\S]*?)\s*-->\s*\n/);
  if (fmMatch) {
    const fmRaw = fmMatch[1];
    raw = raw.slice(fmMatch[0].length);
    for (const part of fmRaw.split('|')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1).trim();
      if (k === 'title') fm.title = v;
      else if (k === 'description') fm.description = v;
      else if (k === 'breadcrumb') {
        // format: Home > Quickstart  (labels only, auto-link)
        fm.breadcrumb = v.split('>').map(s => s.trim());
      } else if (k === 'date') fm.date = v;
      else if (k === 'body-class') fm.bodyClass = v ? ` class="${v}"` : '';
    }
  }

  const headings = extractHeadings(raw);
  const tocHtml = buildToc(headings, ui);

  // base for relative links: depth
  const depth = outRel.split('/').length - 1;
  const base = depth === 0 ? '' : '../'.repeat(depth);

  // hreflang + canonical — only emit existing counterpart
  const { tags: hreflang, canonical } = hreflangTags(outRel, lang);

  // lang switcher
  const switcher = langSwitcher(outRel, lang);

  // breadcrumb: build from fm.breadcrumb labels
  let breadcrumb = '';
  if (fm.breadcrumb && fm.breadcrumb.length) {
    const crumbs = fm.breadcrumb.map((label, i) => {
      if (i === fm.breadcrumb.length - 1) return { label };
      // link crumbs to their pages — map well-known labels
      const map = { 'Home': base + 'index.html', 'Overview': base + 'index.html', 'Guide': base + 'guide/configuration.html', 'Reference': base + 'reference/cli.html' };
      return { label, href: map[label] || '#' };
    });
    breadcrumb = breadcrumbHtml(crumbs);
  }

  const pageMeta = pageMetaHtml(fm.date, ui);

  // header: inject base + switcher
  let header = partials.header.replaceAll('{{base}}', base).replace('{{lang-switcher}}', switcher);
  // mark active nav
  const navActive = outRel.replace(/^it\//, '');
  header = header.replaceAll('data-nav="', 'data-nav="'); // keep
  // add active class
  header = header.replace(`data-nav="${path.basename(navActive)}"`, `data-nav="${path.basename(navActive)}" class="active"`);
  // fallback: also handle exact
  if (!header.includes('class="active"')) {
    // try without ext
  }
  for (const [key, value] of Object.entries(ui)) header = header.replaceAll(`{{${key}}}`, value);

  // sidebar: inject base + active (active class on current page)
  let sidebar = partials.sidebar.replaceAll('{{base}}', base);
  for (const [key, value] of Object.entries(ui)) sidebar = sidebar.replaceAll(`{{${key}}}`, value);
  const pageName = path.basename(outRel);
  // need to handle both plain and sub links; do sub first
  sidebar = sidebar.split(`class="sidebar-link sub" data-page="${pageName}"`).join(`class="sidebar-link sub active" data-page="${pageName}"`);
  sidebar = sidebar.split(`class="sidebar-link" data-page="${pageName}"`).join(`class="sidebar-link active" data-page="${pageName}"`);

  // footer
  let footer = partials.footer.replaceAll('{{base}}', base);
  for (const [key, value] of Object.entries(ui)) footer = footer.replaceAll(`{{${key}}}`, value);

  let html = partials.layout;
  html = html.replaceAll('{{lang}}', lang);
  html = html.replaceAll('{{title}}', escapeHtml(fm.title));
  html = html.replaceAll('{{description}}', escapeHtml(fm.description));
  html = html.replaceAll('{{base}}', base);
  html = html.replaceAll('{{canonical}}', canonical);
  html = html.replaceAll('{{hreflang}}', hreflang);
  html = html.replaceAll('{{body-class}}', fm.bodyClass);
  html = html.replaceAll('{{header}}', header);
  html = html.replaceAll('{{sidebar}}', sidebar);
  html = html.replaceAll('{{breadcrumb}}', breadcrumb);
  html = html.replaceAll('{{page-meta}}', pageMeta);
  html = html.replaceAll('{{content}}', raw.trim());
  html = html.replaceAll('{{footer}}', footer);
  html = html.replaceAll('{{toc}}', tocHtml);

  // ensure output dir
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, html, 'utf8');
  return outRel;
}

function main() {
  const partials = loadPartials();

  // collect src files: docs/src/**/*.html excluding _partials and layout.html
  const files = [];
  function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === '_partials') continue;
        walk(p);
      } else if (e.name.endsWith('.html') && e.name !== 'layout.html') {
        files.push(p);
      }
    }
  }
  walk(SRC);

  if (!files.length) {
    console.log('No src files found in docs/src/. Nothing to build.');
    return;
  }

  const built = [];
  for (const f of files) {
    const rel = buildPage(f, partials);
    built.push(rel);
  }
  console.log(`Built ${built.length} pages:`);
  for (const b of built) console.log('  ' + b);
}

main();
