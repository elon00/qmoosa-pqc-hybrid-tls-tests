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
