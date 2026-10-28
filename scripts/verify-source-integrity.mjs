import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modes = new Set(['all', 'archive', 'source', 'current-head']);
const args = process.argv.slice(2);
if (args.length > 1 || (args.length && !args[0].startsWith('--mode='))) {
  console.error('INTEGRITY_INPUT_ERROR: expected at most one --mode argument');
  process.exit(2);
}
const mode = args.length ? args[0].slice('--mode='.length) : 'all';
if (!modes.has(mode)) {
  console.error(`INTEGRITY_INPUT_ERROR: unsupported mode ${mode}`);
  process.exit(2);
}

try {
  const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, 'integrity-manifest.json'), 'utf8'));
  if (!Array.isArray(manifest.packages) || manifest.packages.length === 0) throw new Error('manifest must contain at least one package');
  const seen = new Set();
  for (const pkg of manifest.packages) {
    if (!pkg || typeof pkg.name !== 'string' || seen.has(pkg.name) ||
        typeof pkg.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(pkg.repository) || pkg.repository.split('/').some(part => part === '.' || part === '..') ||
        !/^[0-9a-f]{40}$/i.test(pkg.sourceCommit ?? '') ||
        !/^[0-9a-f]{64}$/i.test(pkg.sha256 ?? '') ||
        typeof pkg.archivePath !== 'string' || !pkg.archivePath || path.isAbsolute(pkg.archivePath)) throw new Error('malformed or duplicate package identity');
    seen.add(pkg.name);
    const relative = path.relative(rootDir, path.resolve(rootDir, pkg.archivePath));
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('archive must stay inside the tests repository');
    let current = rootDir;
    for (const component of relative.split(path.sep)) {
      current = path.join(current, component);
      if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error('archive symlinks are not accepted');
    }
  }
  let failed = false;
  function gate(label, verify) {
    let gateFailed = false;
    for (const pkg of manifest.packages) {
      try { verify(pkg); console.log(`[PASS] ${label}: ${pkg.name}`); }
      catch (error) { gateFailed = true; console.error(`[FAIL] ${label}: ${pkg.name}: ${error.message}`); }
    }
    console.log(`RESULT: ${label}_${gateFailed ? 'FAIL' : 'PASS'}`);
    failed ||= gateFailed;
  }
  function sibling(pkg) {
    const dir = path.resolve(rootDir, '..', pkg.repository.split('/')[1]);
    if (!fs.existsSync(dir) || !fs.lstatSync(dir).isDirectory() || fs.lstatSync(dir).isSymbolicLink()) throw new Error('required sibling repository is unavailable');
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: dir, encoding: 'utf8', timeout: 10000 }).trim();
    if (fs.realpathSync(top) !== fs.realpathSync(dir)) throw new Error('sibling is not a checkout root');
    return dir;
  }
  console.log(`Mode: ${mode}`);
  if (mode === 'all' || mode === 'archive') gate('ARCHIVE_INTEGRITY', pkg => {
    const archive = path.resolve(rootDir, pkg.archivePath);
    if (!fs.statSync(archive).isFile()) throw new Error('archive is not a regular file');
    const actual = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
    if (actual !== pkg.sha256.toLowerCase()) throw new Error('archive SHA-256 mismatch');
  });
  if (mode === 'all' || mode === 'source') gate('SOURCE_PROVENANCE', pkg => {
    // Ancestry does not prove reproducible source-to-archive derivation.
    execFileSync('git', ['merge-base', '--is-ancestor', pkg.sourceCommit, 'HEAD'], { cwd: sibling(pkg), stdio: 'pipe', timeout: 10000 });
  });
  if (mode === 'all' || mode === 'current-head') gate('CURRENT_HEAD_ALIGNMENT', pkg => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sibling(pkg), encoding: 'utf8', timeout: 10000 }).trim();
    if (head.toLowerCase() !== pkg.sourceCommit.toLowerCase()) throw new Error('HEAD differs from recorded source commit');
  });
  process.exitCode = failed ? 1 : 0;
} catch (error) { console.error(`INTEGRITY_INPUT_ERROR: ${error.message}`); process.exitCode = 2; }
