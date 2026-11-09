// Check repository Markdown without reading ignored files, such as dependencies.
// Run from any directory with: node scripts/check_markdown_encoding.js
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder } = require('node:util');

const root = path.resolve(__dirname, '..');
const names = execFileSync('git', [
  'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '*.md',
], { cwd: root }).toString('utf8').split('\0').filter(Boolean);
const decoder = new TextDecoder('utf-8', { fatal: true });
// Common UTF-8 decoded as Windows-1252/Latin-1, plus replacement characters.
const mojibake = /\u00c3[\u0080-\u00bf\u201a\u0192\u201e\u2026\u2020\u2021\u02c6\u2030\u0160\u2039\u0152\u017d\u2018\u2019\u201c\u201d\u2022\u2013\u2014\u02dc\u2122\u0161\u203a\u0153\u017e\u0178]|\u00c2[\u0080-\u00bf\u20ac\u00a0]|\u00e2[\u0080-\u00bf\u20ac\u201a\u201e\u2026\u2020\u2021\u2030\u2039\u2018\u2019\u201c\u201d\u2022\u2013\u2014\u2122\u203a]|\u00f0\u0178|\ufffd/u;
let errors = 0;
let checked = 0;
for (const name of new Set(names)) {
  const file = path.join(root, name);
  if (!fs.existsSync(file)) continue;
  checked++;
  try {
    const content = decoder.decode(fs.readFileSync(file));
    if (mojibake.test(content)) {
      console.error(`${name}: possible mojibake`);
      errors++;
    }
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    console.error(`${name}: invalid UTF-8`);
    errors++;
  }
}
console.log(`Checked ${checked} Markdown files; ${errors} file(s) with encoding errors.`);
if (errors) process.exitCode = 1;
