import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:test/test.dart';

import 'dart_crypto.dart';

void main() {
  test('RFC 8785 JCS sorts keys', () {
    expect(jcs({'b': 1, 'a': 2}), '{"a":2,"b":1}');
    expect(jcs({'format': 'CKVF', 'version': '1.0'}), '{"format":"CKVF","version":"1.0"}');
  });

  test('SPEC example AAD JCS', () {
    final aad = aadObject(
      VaultContainer(
        format: 'CKVF',
        version: '1.0',
        vaultId: 'ASNFZ4mrze8BI0VniavN7w',
        generation: 1,
        previousGenerationHash: null,
        generationHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        crypto: CryptoParams(aead: 'A256GCM', iv: 'AAECAwQFBgcICQoL'),
        unlockSlots: const [],
        ciphertext: '',
        tag: 'AAAAAAAAAAAAAAAAAAAAAA',
        extensions: const [],
        criticalExtensions: const [],
      ),
    );
    expect(
      jcs(aad),
      '{"critical_extensions":[],"crypto":{"aead":"A256GCM","iv":"AAECAwQFBgcICQoL"},"extensions":[],"format":"CKVF","generation":1,"previous_generation_hash":null,"unlock_slots":[],"vault_id":"ASNFZ4mrze8BI0VniavN7w","version":"1.0"}',
    );
  });

  test('email and dns canonicalization', () {
    expect(canonicalizeEmail('User@Example.COM'), 'user@example.com');
    expect(canonicalizeEmail('  alice@EXAMPLE.com  '), 'alice@example.com');
    expect(canonicalizeDns('Example.COM.'), 'example.com');
    expect(canonicalizeDns('example.com...'), 'example.com');
  });

  test('identity_id examples from SPEC', () async {
    final crypto = DartCkvfCrypto();
    final emailId = await identityId('email', 'user@example.com', crypto);
    final dnsId = await identityId('dns', 'example.com', crypto);
    expect(emailId, 'tmwIJmeStJDSo9giG47rc8MKlVNxXPBKhG1GIcReptA');
    expect(dnsId, 'LpMoG_ozO2qxNonqsDwgJUBJEvma97aY8Z9q1njrZ-M');
  });

  test('short key id from digest prefix', () {
    expect(shortKeyIdFromDigest([0x64, 0x8a, 0xa5, 0xc5, 0, 0, 0, 0]), '648A-A5C5');
  });

  test('merge unions keys and escalates status', () {
    KeyRecord key(String id, String status) => KeyRecord(
          absoluteKeyId: id,
          shortKeyId: '0000-0000',
          family: 'openpgp',
          algorithm: 'Ed25519',
          encoding: 'openpgp-tsk',
          purpose: const ['sign'],
          publicKey: 'AA',
          privateKey: 'BB',
          createdAt: '2026-08-17T00:00:00Z',
          status: status,
        );
    VaultPayload payload(List<KeyRecord> keys) => VaultPayload(
          identity: Identity(
            type: 'email',
            value: 'a@example.com',
            identityId: 'x',
          ),
          msk: MskState(
            current: MskCurrent(
              mskId: 'm',
              algorithm: 'Ed25519',
              publicKey: 'p',
              privateKey: 's',
              activatedAt: '2026-08-17T00:00:00Z',
            ),
            history: const [],
          ),
          keys: keys,
          preferredKeys: {},
          metadata: VaultMetadata(
            createdAt: '2026-08-17T00:00:00Z',
            updatedAt: '2026-08-17T00:00:00Z',
          ),
          tombstones: const [],
          extensions: const [],
          criticalExtensions: const [],
        );
    final merged = mergePayloads(
      payload([key('K1', 'active'), key('K2', 'active'), key('K3', 'active')]),
      payload([key('K1', 'retired'), key('K2', 'active'), key('K4', 'active')]),
      const [],
      const [],
    );
    expect(
      merged.payload.keys.map((k) => k.absoluteKeyId).toList()..sort(),
      ['K1', 'K2', 'K3', 'K4'],
    );
    expect(
      merged.payload.keys.firstWhere((k) => k.absoluteKeyId == 'K1').status,
      'retired',
    );
  });

  test('utf8 helper roundtrip', () {
    expect(utf8Decode(utf8Encode('CKVF')), 'CKVF');
  });

  test('capability queries', () {
    expect(Ckvf.canReadVersion('1.0'), isTrue);
    expect(Ckvf.canWriteVersion('1.0'), isTrue);
    expect(Ckvf.canReadVersion('2.0'), isFalse);
    expect(Ckvf.supportedUnlockMethods(), contains('password-argon2id'));
  });

  test('MSK stays Ed25519; pq family remains forbidden', () {
    expect(mskAlgorithms, ['Ed25519', 'mldsa65-ed25519']);
    expect(isForbiddenFamily('pq'), isTrue);
    expect(isForbiddenFamily('pqc'), isTrue);
    expect(keyFamilies, containsAll(['openpgp', 'smime']));
    expect(algorithmSuites, containsAll(['rsa', 'ecc', 'pqc']));
    expect(algorithmSuiteFromAlgorithm('Ed25519'), 'ecc');
    expect(algorithmSuiteFromAlgorithm('ML-DSA-65+Ed25519'), 'pqc');
    expect(algorithmSuiteFromAlgorithm('rsa4096'), 'rsa');
  });

  test('v4 OpenPGP public material length for RFC 9980 IDs 30/35', () {
    // Tag 5 secret: v4, created, alg 30, then 32+1952 public octets.
    final body = Uint8List(6 + 32 + 1952);
    body[0] = 4;
    body[5] = 30;
    final tsk = encodeNewFormatPacket(5, body);
    final pub = canonicalOpenPgpPublicKey(const [], tsk);
    expect(pub.first & 0x3f, 6);
  });
}
