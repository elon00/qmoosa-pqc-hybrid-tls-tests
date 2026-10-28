import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requireRoot = createRequire(import.meta.url);
const packageNames = ['protocol', 'engine', 'sdk'].map(role => '@qmoosa/pqc-hybrid-tls-' + role);
test('engine and SDK resolve the same installed protocol and engine packages', () => {
  const engine = requireRoot.resolve(packageNames[1]);
  const sdk = requireRoot.resolve(packageNames[2]);
  const protocol = fs.realpathSync(requireRoot.resolve(packageNames[0]));
  assert.equal(fs.realpathSync(createRequire(engine).resolve(packageNames[0])), protocol);
  assert.equal(fs.realpathSync(createRequire(sdk).resolve(packageNames[0])), protocol);
  assert.equal(fs.realpathSync(createRequire(sdk).resolve(packageNames[1])), fs.realpathSync(engine));
});
test('all local packages have integrity-addressed archive entries instead of dangling links', () => {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  for (const name of packageNames) {
    const entry = lock.packages['node_modules/' + name];
    assert.ok(entry && !entry.link, 'Expected an installed archive for ' + name);
    assert.match(entry.resolved, /^file:packages\/[A-Za-z0-9_.-]+\.tgz$/);
    const archive = fs.readFileSync(path.join(root, entry.resolved.slice(5)));
    const integrity = 'sha512-' + crypto.createHash('sha512').update(archive).digest('base64');
    assert.equal(entry.integrity, integrity);
  }
  assert.ok(!Object.keys(lock.packages).some(name => name.includes('/@qmoosa/qmoosa-pqc-')));
});
test('root overrides preserve the direct committed archive specifiers', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const name of packageNames) assert.equal(manifest.overrides[name], '$' + name);
});
