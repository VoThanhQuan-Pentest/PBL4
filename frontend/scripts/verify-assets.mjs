import { promises as fs } from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../public/assets/images');
const manifest = JSON.parse(await fs.readFile(path.resolve(import.meta.dirname, '../asset-manifest.json'), 'utf8'));
const maxBytes = 500 * 1024;
const missing = [];
const oversized = [];

for (const target of Object.values(manifest)) {
  const file = path.join(root, target.replace('./assets/images/', ''));
  try {
    const size = (await fs.stat(file)).size;
    if (size > maxBytes) oversized.push(`${target} (${size} bytes)`);
  } catch {
    missing.push(target);
  }
}

if (missing.length || oversized.length) {
  console.error(JSON.stringify({ missing, oversized }, null, 2));
  process.exit(1);
}

console.log(`Verified ${Object.keys(manifest).length} optimized assets.`);
