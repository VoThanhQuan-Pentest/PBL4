import { promises as fs } from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '../..');
const manifest = JSON.parse(await fs.readFile(path.resolve(import.meta.dirname, '../asset-manifest.json'), 'utf8'));
const candidates = [
  'frontend/index.html',
  'frontend/src/legacy/main.js',
  'db-init/product_images_seed.sql',
  'db-init/worldcup_2026_kits_patch.sql',
  'docs/product-image-list.md'
];

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

let changedFiles = 0;
for (const relativePath of candidates) {
  const file = path.join(projectRoot, relativePath);
  let source;
  try {
    source = await fs.readFile(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') continue;
    throw error;
  }
  let next = source;
  for (const [from, to] of Object.entries(manifest)) {
    next = next.replace(new RegExp(`${escapeRegex(from)}(?!\\.webp)`, 'g'), to);
  }
  next = next.replaceAll('.webp.webp', '.webp');
  if (next !== source) {
    await fs.writeFile(file, next);
    changedFiles += 1;
  }
}

console.log(`Updated references in ${changedFiles} files.`);
