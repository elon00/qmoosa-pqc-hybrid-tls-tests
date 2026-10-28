# QMOOSA Post-Quantum Hybrid TLS Tests & Multi-Repo Reality Gates

Full-spectrum supply-chain integrity, source provenance, multi-repo integration, and adversarial negative control test harness for QMOOSA NIST FIPS 203 ML-KEM-768 + RFC 8446 X25519 Hybrid TLS 1.3 key exchange.

## Reality Gate Architecture
1. **Gate 1: Archive Integrity Verification**: Strict SHA-256 validation of immutable protocol, engine, and SDK distribution tarballs.
2. **Gate 2: Source Provenance Verification**: Cryptographic git history ancestor validation against pinned source commits.
3. **Gate 3: Current-HEAD Alignment**: Validation that local workspace repositories match pinned release hashes.
4. **Gate 4: Integration & Negative Controls**: End-to-end multi-message bidirectional transport testing and 14 adversarial negative attack controls.

## Security Governance
- **Zero Cloud Spend Invariant**: $0.00 spent across all cloud and blockchain resources.
- **Production Certification Lock**: Mainnet/public testnets strictly locked at `0 / 1,000 CERTIFIED`.

## Running Gates Locally
```bash
npm install
npm test
```

## Evidence limits

The provenance gates fail if a required sibling checkout is missing or the selected mode is unknown. Archive mode checks recorded SHA-256 digests. Source mode checks Git ancestry; current-head mode checks exact recorded commit equality. These do not prove that the archives were reproducibly built from those sources. Frozen dependency installation and current engine/SDK compatibility remain separate acceptance gates.

Run `node --test tests/provenance-gates.test.mjs` for the dependency-free regression suite. It uses temporary local Git checkouts and makes no external network calls.

CI uses recorded action/source commits, exact Node 24.19.0 and frozen `npm ci --ignore-scripts` installs. Missing or broken locks fail visibly; the workflow no longer deletes lockfiles or manually replaces installed packages. Frozen archive dependency links and current authenticated-engine compatibility remain unresolved acceptance work.

## Frozen archive installation

Root npm overrides resolve the engine/SDK transitive local dependencies to the same committed archives used directly by this test suite. Package archive bytes and recorded source commits are unchanged. The regenerated lock removes dangling nested links and preserves the existing registry package versions.

Run `npm ci --ignore-scripts --no-audit --no-fund --engine-strict --registry=https://registry.npmjs.org`, then `npm run test:dependencies`. The complete `npm test` command also requires the recorded sibling source checkouts for provenance verification. No lockfile is deleted during CI. Passing these archive-level tests does not establish authenticated TLS transport, current consumer compatibility or production readiness.
