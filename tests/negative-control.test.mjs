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
  HybridTlsServer
} from '@qmoosa/pqc-hybrid-tls-sdk';

test('Negative Control 1: Bit Corruption in ML-KEM Ciphertext Prevents Key Agreement', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);

  // Corrupt a byte in the ML-KEM ciphertext portion of ServerKeyShare (offset 32..1120)
  const corruptedServerShare = new Uint8Array(serverKeyShare);
  corruptedServerShare[50] ^= 0x55;

  const clientSession = client.completeHandshake(corruptedServerShare);

  const clientKeys = clientSession.getSessionKeys();
  const serverKeys = serverSession.getSessionKeys();

  // Due to implicit rejection in ML-KEM decapsulation, client derives a pseudo-random secret that DOES NOT match server
  assert.equal(
    constantTimeEqual(clientKeys.clientTrafficSecret, serverKeys.clientTrafficSecret),
    false,
    'Corrupted ML-KEM ciphertext must not produce matching traffic secrets'
  );
});

test('Negative Control 2: Bit Corruption in Classical X25519 Share Prevents Key Agreement', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);

  // Corrupt a byte in the X25519 public key portion of ServerKeyShare (offset 0..32)
  const corruptedServerShare = new Uint8Array(serverKeyShare);
  corruptedServerShare[10] ^= 0xaa;

  try {
    const clientSession = client.completeHandshake(corruptedServerShare);
    const clientKeys = clientSession.getSessionKeys();
    const serverKeys = serverSession.getSessionKeys();

    assert.equal(
      constantTimeEqual(clientKeys.clientTrafficSecret, serverKeys.clientTrafficSecret),
      false,
      'Corrupted X25519 key share must fail traffic secret agreement'
    );
  } catch (err) {
    assert.ok(err, 'Expected error on invalid curve point');
  }
});

test('Negative Control 3: Truncated ClientKeyShare Wire Payload Rejected', () => {
  const truncatedShare = new Uint8Array(500); // Expected 1,216 bytes
  assert.throws(
    () => deserializeClientKeyShare(truncatedShare),
    /INVALID_CLIENT_KEY_SHARE_LENGTH/
  );
});

test('Negative Control 4: Overlong ClientKeyShare Wire Payload Rejected', () => {
  const overlongShare = new Uint8Array(2000); // Expected 1,216 bytes
  assert.throws(
    () => deserializeClientKeyShare(overlongShare),
    /INVALID_CLIENT_KEY_SHARE_LENGTH/
  );
});

test('Negative Control 5: Truncated ServerKeyShare Wire Payload Rejected', () => {
  const truncatedShare = new Uint8Array(500); // Expected 1,120 bytes
  assert.throws(
    () => deserializeServerKeyShare(truncatedShare),
    /INVALID_SERVER_KEY_SHARE_LENGTH/
  );
});

test('Negative Control 6: Overlong ServerKeyShare Wire Payload Rejected', () => {
  const overlongShare = new Uint8Array(1500); // Expected 1,120 bytes
  assert.throws(
    () => deserializeServerKeyShare(overlongShare),
    /INVALID_SERVER_KEY_SHARE_LENGTH/
  );
});

test('Negative Control 7: Replay Attack with Duplicate Sequence Number Rejected', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  const record0 = clientSession.send('Authorization: transfer 1000 QMOOSA');
  const d0 = serverSession.receive(record0);
  assert.equal(new TextDecoder().decode(d0), 'Authorization: transfer 1000 QMOOSA');

  // Attacker attempts to replay record0
  assert.throws(
    () => serverSession.receive(record0),
    /SEQUENCE_NUMBER_MISMATCH/
  );
});

test('Negative Control 8: Out-of-Order Sequence Number Gap Rejected', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  // Attacker crafts record with gap in sequence number (e.g. 5n instead of 0n)
  const forgedRecord = {
    header: { contentType: 23, legacyVersion: 0x0303, length: 32 },
    ciphertext: new Uint8Array(16),
    authTag: new Uint8Array(16),
    sequenceNumber: 5n
  };

  assert.throws(
    () => serverSession.receive(forgedRecord),
    /SEQUENCE_NUMBER_MISMATCH/
  );
});

test('Negative Control 9: Tampered AES-256-GCM Ciphertext Byte Fails Authentication', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  const genuineRecord = clientSession.send('Confidential Financial Payload');

  // Attacker flips 1 bit in ciphertext
  const tamperedCiphertext = new Uint8Array(genuineRecord.ciphertext);
  tamperedCiphertext[0] ^= 0x01;

  const tamperedRecord = {
    ...genuineRecord,
    ciphertext: tamperedCiphertext
  };

  assert.throws(
    () => serverSession.receive(tamperedRecord),
    /TLS_RECORD_AUTHENTICATION_FAILURE|DECRYPTION_FAILED|Unsupported state or unable to authenticate data|bad decrypt/
  );
});

test('Negative Control 10: Tampered AES-256-GCM Auth Tag Fails Authentication', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);
  const clientSession = client.completeHandshake(serverKeyShare);

  const genuineRecord = clientSession.send('Confidential Financial Payload');

  // Attacker flips 1 bit in auth tag
  const tamperedTag = new Uint8Array(genuineRecord.authTag);
  tamperedTag[0] ^= 0xff;

  const tamperedRecord = {
    ...genuineRecord,
    authTag: tamperedTag
  };

  assert.throws(
    () => serverSession.receive(tamperedRecord),
    /TLS_RECORD_AUTHENTICATION_FAILURE|DECRYPTION_FAILED|Unsupported state or unable to authenticate data|bad decrypt/
  );
});

test('Negative Control 11: Calling completeHandshake Before startHandshake Throws', () => {
  const client = new HybridTlsClient();
  const dummyServerShare = new Uint8Array(1120);

  assert.throws(
    () => client.completeHandshake(dummyServerShare),
    /HANDSHAKE_STATE_INVALID/
  );
});

test('Negative Control 12: Mismatched Transcript Context Produces Divergent Keys', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const contextA = new TextEncoder().encode('Transcript-Binding-A');
  const contextB = new TextEncoder().encode('Transcript-Binding-B');

  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare, contextA);
  const clientSession = client.completeHandshake(serverKeyShare, contextB);

  const clientKeys = clientSession.getSessionKeys();
  const serverKeys = serverSession.getSessionKeys();

  assert.equal(
    constantTimeEqual(clientKeys.clientTrafficSecret, serverKeys.clientTrafficSecret),
    false,
    'Mismatched transcript context must yield mismatched session keys'
  );
});

test('Negative Control 13: Desynchronized Sessions Inter-Session Cross-Decryption Failure', () => {
  const client1 = new HybridTlsClient();
  const server1 = new HybridTlsServer();
  const cShare1 = client1.startHandshake();
  const sShare1 = server1.handleClientKeyShare(cShare1.clientKeyShare);
  const session1 = client1.completeHandshake(sShare1.serverKeyShare);

  const client2 = new HybridTlsClient();
  const server2 = new HybridTlsServer();
  const cShare2 = client2.startHandshake();
  const sShare2 = server2.handleClientKeyShare(cShare2.clientKeyShare);
  const session2 = client2.completeHandshake(sShare2.serverKeyShare);

  const record1 = session1.send('Confidential Secret Message for Session 1');

  // Attempting to feed session 1's record into session 2's server
  assert.throws(
    () => sShare2.session.receive(record1),
    /TLS_RECORD_AUTHENTICATION_FAILURE|DECRYPTION_FAILED|Unsupported state or unable to authenticate data|bad decrypt/
  );
});

test('Negative Control 14: All-Zero ML-KEM Ciphertext Does Not Match genuine secret', () => {
  const client = new HybridTlsClient();
  const server = new HybridTlsServer();

  const { clientKeyShare } = client.startHandshake();
  const { serverKeyShare, session: serverSession } = server.handleClientKeyShare(clientKeyShare);

  // Substitute ML-KEM ciphertext with all zeros
  const zeroCiphertextShare = new Uint8Array(serverKeyShare);
  zeroCiphertextShare.fill(0, 32, 1120);

  const clientSession = client.completeHandshake(zeroCiphertextShare);
  const clientKeys = clientSession.getSessionKeys();
  const serverKeys = serverSession.getSessionKeys();

  assert.equal(
    constantTimeEqual(clientKeys.clientTrafficSecret, serverKeys.clientTrafficSecret),
    false,
    'All-zero ciphertext must not yield matching traffic secret'
  );
});
