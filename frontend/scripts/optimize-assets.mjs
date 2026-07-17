import { promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import sharp from 'sharp';

const root = path.resolve(import.meta.dirname, '../public/assets/images');
const manifestPath = path.resolve(import.meta.dirname, '../asset-manifest.json');
const shouldPrune = process.argv.includes('--prune');
const extensions = new Set(['.jpg', '.jpeg', '.png']);
const maxBytes = 500 * 1024;

async function listFiles(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files = await Promise.all(entries.map(async entry => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? listFiles(target) : [target];
  }));
  return files.flat();
}

async function encode(source, destination) {
  const attempts = [
    { width: 1600, quality: 80 },
    { width: 1400, quality: 72 },
    { width: 1200, quality: 64 }
  ];

  for (const attempt of attempts) {
    await sharp(source, { animated: false })
      .rotate()
      .resize({ width: attempt.width, height: attempt.width, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: attempt.quality, alphaQuality: 90, effort: 6 })
      .toFile(destination);
    if ((await fs.stat(destination)).size <= maxBytes) {
      return;
    }
  }
}

const allFiles = await listFiles(root);
const files = allFiles.filter(file => extensions.has(path.extname(file).toLowerCase()));
const existingWebp = allFiles.filter(file => path.extname(file).toLowerCase() === '.webp');
let manifest = {};
try {
  manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

for (const source of files) {
  const destination = `${source}.webp`;
  await encode(source, destination);
  const from = `./assets/images/${path.relative(root, source).split(path.sep).join('/')}`;
  manifest[from] = `${from}.webp`;
}

await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

for (const source of existingWebp) {
  if ((await fs.stat(source)).size <= maxBytes) continue;
  const temporary = `${source}.tmp`;
  await encode(source, temporary);
  await fs.rename(temporary, source);
}

if (shouldPrune) {
  await Promise.all(files.map(file => fs.unlink(file)));
}

console.log(`Optimized ${files.length} images${shouldPrune ? ' and removed source files' : ''}.`);
