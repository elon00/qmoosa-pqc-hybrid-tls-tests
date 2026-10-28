import test from 'node:test';
import assert from 'node:assert/strict';
import {
  X25519_MLKEM_768,
  constantTimeEqual,
  deserializeClientKeyShare,
  deserializeServerKeyShare
} from '@qmoosa/pqc-hybrid-tls-protocol';
import {
  HybridTlsEngine
} from '@qmoosa/pqc-hybrid-tls-engine';
import {
  HybridTlsClient,
  HybridTlsServer,
  bytesToHex
} from '@qmoosa/pqc-hybrid-tls-sdk';

test('Archived SDK: raw hybrid key-exchange symmetry', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  // 1. Client initiates handshake and emits ClientKeyShare
  const { clientKeyShare, clientKeyShareBase64Url } = client.startHandshake();
  assert.equal(clientKeyShare.byteLength, 1216, 'ClientKeyShare wire must be 1,216 bytes');
  assert.ok(clientKeyShareBase64Url.length > 0, 'Must produce valid base64url representation');

  // Verify protocol wire deserialization
  const parsedClientShare = deserializeClientKeyShare(clientKeyShare);
  assert.equal(parsedClientShare.x25519PublicKey.length, 32);
  assert.equal(parsedClientShare.mlkemEncapsulationKey.length, 1184);

  // 2. Server processes ClientKeyShare and responds with ServerKeyShare + server session
  const { serverKeyShare, serverKeyShareBase64Url, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  assert.equal(serverKeyShare.byteLength, 1120, 'ServerKeyShare wire must be 1,120 bytes');
  assert.ok(serverKeyShareBase64Url.length > 0, 'Must produce valid base64url representation');

  // Verify protocol wire deserialization
  const parsedServerShare = deserializeServerKeyShare(serverKeyShare);
  assert.equal(parsedServerShare.x25519PublicKey.length, 32);
  assert.equal(parsedServerShare.mlkemCiphertext.length, 1088);

  // 3. Client processes ServerKeyShare to establish client session
  const clientSession = client.completeHandshake(serverKeyShare);

  assert.ok(clientSession, 'Client session must be established');
  assert.ok(serverSession, 'Server session must be established');

  const clientKeys = clientSession.getSessionKeys();
  const serverKeys = serverSession.getSessionKeys();

  // Both sides must derive identical symmetric keys and IVs
  assert.ok(constantTimeEqual(clientKeys.clientWriteKey, serverKeys.clientWriteKey), 'Client write keys must match');
  assert.ok(constantTimeEqual(clientKeys.serverWriteKey, serverKeys.serverWriteKey), 'Server write keys must match');
  assert.ok(constantTimeEqual(clientKeys.clientWriteIV, serverKeys.clientWriteIV), 'Client write IVs must match');
  assert.ok(constantTimeEqual(clientKeys.serverWriteIV, serverKeys.serverWriteIV), 'Server write IVs must match');
  assert.ok(constantTimeEqual(clientKeys.clientTrafficSecret, serverKeys.clientTrafficSecret), 'Client traffic secrets must match');
  assert.ok(constantTimeEqual(clientKeys.serverTrafficSecret, serverKeys.serverTrafficSecret), 'Server traffic secrets must match');
});

test('Archived SDK: bidirectional raw AEAD record round trips', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  // Transmit 10 messages from client to server
  for (let i = 0; i < 10; i++) {
    const plaintext = `Quantum-Resistant Financial Ledger Event #${i}: transfer 100 QMOOSA`;
    const record = clientSession.send(plaintext);
    assert.equal(record.sequenceNumber, BigInt(i));

    const decrypted = serverSession.receive(record);
    const decryptedStr = new TextDecoder().decode(decrypted);
    assert.equal(decryptedStr, plaintext);
  }

  // Transmit 5 responses from server to client
  for (let j = 0; j < 5; j++) {
    const ack = `ACK Ledger Event #${j}: confirmed post-quantum state anchor`;
    const record = serverSession.send(ack);
    assert.equal(record.sequenceNumber, BigInt(j));

    const decrypted = clientSession.receive(record);
    const decryptedStr = new TextDecoder().decode(decrypted);
    assert.equal(decryptedStr, ack);
  }
});

test('Archived SDK: 16 KiB raw record round trip', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  // Create a 16 KB block of state (standard RFC 8446 TLS max plaintext record length)
  const largeBlock = Buffer.alloc(16 * 1024, 0x42);
  const record = clientSession.send(new Uint8Array(largeBlock));
  const decrypted = serverSession.receive(record);

  assert.equal(decrypted.length, 16 * 1024);
  assert.ok(Buffer.from(decrypted).equals(largeBlock), '16 KB payload must round-trip with byte-for-byte fidelity');
});
