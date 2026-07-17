import { parse } from 'acorn';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const sourceFile = path.resolve(import.meta.dirname, '../src/legacy/main.js');
const write = process.argv.includes('--write');
const source = await fs.readFile(sourceFile, 'utf8');
const program = parse(source, { ecmaVersion: 'latest', sourceType: 'module' });
const domReady = program.body.find(statement =>
  statement.type === 'ExpressionStatement'
  && statement.expression.type === 'CallExpression'
  && statement.expression.callee.type === 'MemberExpression'
  && statement.expression.callee.object.name === 'document'
  && statement.expression.callee.property.name === 'addEventListener'
  && statement.expression.arguments[0]?.value === 'DOMContentLoaded'
);

if (!domReady || domReady.expression.arguments[1]?.body?.type !== 'BlockStatement') {
  throw new Error('Unable to locate the DOMContentLoaded application scope.');
}

const body = domReady.expression.arguments[1].body.body;
const groups = new Map();
for (const statement of body) {
  if (statement.type !== 'FunctionDeclaration') continue;
  const name = statement.id.name;
  groups.set(name, [...(groups.get(name) ?? []), statement]);
}

const obsolete = [...groups.values()].flatMap(declarations => declarations.slice(0, -1));
console.log(`Found ${obsolete.length} shadowed function declarations across ${[...groups.values()].filter(group => group.length > 1).length} names.`);
if (!write || obsolete.length === 0) process.exit(0);

let next = source;
for (const declaration of obsolete.sort((left, right) => right.start - left.start)) {
  next = `${next.slice(0, declaration.start)}\n/* Removed duplicate ${declaration.id.name}; the later implementation is authoritative. */\n${next.slice(declaration.end)}`;
}
await fs.writeFile(sourceFile, next);
