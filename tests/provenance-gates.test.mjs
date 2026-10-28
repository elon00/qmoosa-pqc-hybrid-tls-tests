import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../scripts/verify-source-integrity.mjs');
function fixture(t, checkout = false) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-provenance-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'tests');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.copyFileSync(source, path.join(root, 'scripts/gate.mjs'));
  const archive = Buffer.from('non-secret integrity fixture');
  fs.writeFileSync(path.join(root, 'fixture.tgz'), archive);
  const pkg = { name: '@qmoosa/fixture', repository: 'elon00/fixture', sourceCommit: '1'.repeat(40), archivePath: 'fixture.tgz', sha256: crypto.createHash('sha256').update(archive).digest('hex') };
  const sibling = path.join(base, 'fixture');
  const git = (...args) => execFileSync('git', args, { cwd: sibling, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  function commit(text) {
    fs.writeFileSync(path.join(sibling, 'fixture.txt'), text); git('add', 'fixture.txt');
    git('-c', 'user.name=Local Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture');
    return git('rev-parse', 'HEAD');
  }
  if (checkout) { fs.mkdirSync(sibling); git('init'); pkg.sourceCommit = commit('initial'); }
  function manifest(packages = [pkg]) { fs.writeFileSync(path.join(root, 'integrity-manifest.json'), JSON.stringify({ packages })); }
  manifest();
  return { root, pkg, manifest, commit, run(mode) { return spawnSync(process.execPath, ['scripts/gate.mjs', '--mode=' + mode], { cwd: root, encoding: 'utf8', timeout: 15000 }); } };
}
test('archive mode verifies actual bytes and rejects tampering', t => {
  const f = fixture(t); assert.equal(f.run('archive').status, 0);
  fs.appendFileSync(path.join(f.root, 'fixture.tgz'), 'tampered');
  const bad = f.run('archive'); assert.equal(bad.status, 1); assert.match(bad.stdout, /ARCHIVE_INTEGRITY_FAIL/);
});
test('missing siblings fail ancestry, current-head and all gates', t => {
  const f = fixture(t);
  for (const mode of ['source', 'current-head', 'all']) {
    const result = f.run(mode); assert.equal(result.status, 1); assert.match(result.stderr, /required sibling repository is unavailable/);
  }
});
test('unsupported mode cannot silently succeed', t => {
  const f = fixture(t); assert.equal(f.run('typo').status, 2); assert.doesNotMatch(f.run('typo').stdout, /_PASS/);
});
test('empty manifests cannot make a vacuous gate pass', t => {
  const f = fixture(t); f.manifest([]); assert.equal(f.run('archive').status, 2);
});
test('archive traversal and duplicate identities fail closed', t => {
  const f = fixture(t); f.pkg.archivePath = '../outside.tgz'; f.manifest(); assert.equal(f.run('archive').status, 2);
  f.pkg.archivePath = 'fixture.tgz'; f.manifest([f.pkg, f.pkg]); assert.equal(f.run('archive').status, 2);
});
test('malformed commits are rejected before invoking Git', t => {
  const f = fixture(t); f.pkg.sourceCommit = 'HEAD; echo injected'; f.manifest(); assert.equal(f.run('source').status, 2);
});
test('dot repository identities cannot select a parent checkout', t => {
  const f = fixture(t); f.pkg.repository = 'elon00/..'; f.manifest(); assert.equal(f.run('source').status, 2);
});
test('matching checkout passes; later HEAD fails strict alignment', t => {
  const f = fixture(t, true); assert.equal(f.run('all').status, 0);
  f.commit('later'); assert.equal(f.run('source').status, 0); assert.equal(f.run('current-head').status, 1);
});
test('unknown source commits cannot pass ancestry', t => {
  const f = fixture(t, true); f.pkg.sourceCommit = '2'.repeat(40); f.manifest(); assert.equal(f.run('source').status, 1);
});
