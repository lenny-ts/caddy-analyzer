#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Check generated changelog anchors after build-docs.js.
const html = fs.readFileSync(path.join(__dirname, '../docs/changelog.html'), 'utf8');
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
const targets = new Set(ids);
assert.equal(targets.size, ids.length, 'Duplicate changelog anchors');
const toc = html.match(/<nav class="doc-toc"[\s\S]*?<\/nav>/);
assert.ok(toc, 'Missing changelog table of contents');
const links = [...toc[0].matchAll(/href="#([^"]+)"/g)];
assert.ok(links.length, 'Empty changelog table of contents');
for (const [, id] of links) {
  assert.ok(targets.has(id), `Missing changelog anchor: ${id}`);
}
console.log(`Changelog anchors: PASS (${links.length} TOC links, no duplicate IDs)`);
