import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../', import.meta.url));
const target = process.argv[2];
if (process.argv.length !== 3 || !target || !isAbsolute(target) || existsSync(target)) {
  throw new Error('Usage: node tools/stage-runtime.mjs <new absolute runtime directory>');
}

const compiled = join(source, 'dist', 'src');
const files = readdirSync(compiled, { withFileTypes: true })
  .filter(entry => entry.isFile() && entry.name.endsWith('.js'))
  .map(entry => entry.name);
if (files.length !== 46 || !files.includes('companion.js')) {
  throw new Error('Build XMem from a clean checkout before staging the runtime.');
}

const output = resolve(target);
mkdirSync(output);
const destination = join(output, 'dist', 'src');
mkdirSync(destination, { recursive: true });
for (const file of files) copyFileSync(join(compiled, file), join(destination, file));
for (const file of ['package.json', 'npm-shrinkwrap.json']) {
  copyFileSync(join(source, file), join(output, file));
}
console.log(output);
