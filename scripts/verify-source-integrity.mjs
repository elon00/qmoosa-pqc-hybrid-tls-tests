import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const manifestPath = path.join(rootDir, 'integrity-manifest.json');

if (!fs.existsSync(manifestPath)) {
  console.error(`FATAL: integrity-manifest.json not found at ${manifestPath}`);
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const args = process.argv.slice(2);
let mode = 'all';
for (const arg of args) {
  if (arg.startsWith('--mode=')) {
    mode = arg.split('=')[1];
  }
}

console.log('================================================================');
console.log('=== QMOOSA PQC HYBRID TLS SUPPLY-CHAIN INTEGRITY & PROVENANCE ===');
console.log(`Mission:  ${manifest.mission}`);
console.log(`Mode:     ${mode.toUpperCase()}`);
console.log(`Manifest: Generated ${manifest.generatedAt}`);
console.log('================================================================\n');

let archiveIntegrityFailed = false;
let sourceProvenanceFailed = false;
let currentHeadFailed = false;

// GATE 1: STRICT SHA-256 ARCHIVE CHECKSUM GATE
if (mode === 'all' || mode === 'archive') {
  console.log(`--- [GATE 1: ARCHIVE INTEGRITY VERIFICATION] ---`);
  for (const pkg of manifest.packages) {
    const archiveFullPath = path.join(rootDir, pkg.archivePath);
    if (!fs.existsSync(archiveFullPath)) {
      console.error(`  [FAIL] Missing archive: ${pkg.archivePath}`);
      archiveIntegrityFailed = true;
      continue;
    }

    const fileBuffer = fs.readFileSync(archiveFullPath);
    const calculatedHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    if (calculatedHash.toLowerCase() !== pkg.sha256.toLowerCase()) {
      console.error(`  [FAIL] SHA-256 mismatch for ${pkg.name}@${pkg.version}`);
      console.error(`         Expected: ${pkg.sha256}`);
      console.error(`         Actual:   ${calculatedHash}`);
      archiveIntegrityFailed = true;
    } else {
      console.log(`  [PASS] ${pkg.name}@${pkg.version} archive SHA-256 verified (${calculatedHash.substring(0, 16)}...)`);
    }
  }

  if (archiveIntegrityFailed) {
    console.error('\nRESULT: ARCHIVE_INTEGRITY_FAIL');
    process.exit(1);
  } else {
    console.log('\nRESULT: ARCHIVE_INTEGRITY_PASS');
  }
}

// GATE 2: SOURCE PROVENANCE ANCESTRY VERIFICATION
if (mode === 'all' || mode === 'source') {
  console.log(`\n--- [GATE 2: SOURCE PROVENANCE VERIFICATION] ---`);

  for (const pkg of manifest.packages) {
    const repoBaseName = pkg.repository.split('/')[1];
    const siblingDir = path.resolve(rootDir, '..', repoBaseName);

    if (!fs.existsSync(siblingDir)) {
      console.warn(`  [SKIP] Local sibling repository ${siblingDir} not available; checking git ancestry skipped`);
      continue;
    }

    try {
      execSync(`git merge-base --is-ancestor ${pkg.sourceCommit} HEAD`, {
        cwd: siblingDir,
        stdio: 'pipe'
      });
      console.log(`  [PASS] ${pkg.repository} provenance established at ${pkg.sourceCommit.substring(0, 7)}`);
    } catch (err) {
      console.error(`  [FAIL] ${pkg.repository} commit ${pkg.sourceCommit} is not an ancestor of HEAD in ${siblingDir}`);
      sourceProvenanceFailed = true;
    }
  }

  if (sourceProvenanceFailed) {
    console.error('\nRESULT: SOURCE_PROVENANCE_FAIL');
    process.exit(1);
  } else {
    console.log('\nRESULT: SOURCE_PROVENANCE_PASS');
  }
}

// GATE 3: STRICT CURRENT-HEAD ALIGNMENT GATE
if (mode === 'all' || mode === 'current-head') {
  console.log(`\n--- [GATE 3: CURRENT-HEAD ALIGNMENT VERIFICATION] ---`);

  for (const pkg of manifest.packages) {
    const repoBaseName = pkg.repository.split('/')[1];
    const siblingDir = path.resolve(rootDir, '..', repoBaseName);

    if (!fs.existsSync(siblingDir)) {
      console.warn(`  [SKIP] Local sibling repository ${siblingDir} not found; skipping current-head alignment`);
      continue;
    }

    try {
      const currentCommit = execSync('git rev-parse HEAD', { cwd: siblingDir, stdio: 'pipe' }).toString().trim();
      if (currentCommit.toLowerCase() !== pkg.sourceCommit.toLowerCase()) {
        console.error(`  [FAIL] ${repoBaseName} HEAD mismatch!`);
        console.error(`         Expected (pinned in manifest): ${pkg.sourceCommit}`);
        console.error(`         Actual (in sibling repo):       ${currentCommit}`);
        currentHeadFailed = true;
      } else {
        console.log(`  [PASS] ${repoBaseName} HEAD strictly aligned with manifest (${pkg.sourceCommit.substring(0, 7)})`);
      }
    } catch (err) {
      console.error(`  [FAIL] Could not query git HEAD for ${siblingDir}`);
      currentHeadFailed = true;
    }
  }

  if (currentHeadFailed) {
    console.error('\nRESULT: CURRENT_HEAD_ALIGNMENT_FAIL');
    process.exit(1);
  } else {
    console.log('\nRESULT: CURRENT_HEAD_ALIGNMENT_PASS');
  }
}
