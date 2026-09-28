import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:test/test.dart';

import 'dart_crypto.dart';

void main() {
  final crypto = DartCkvfCrypto();

  test('SHA-256 of abc', () async {
    final digest = await crypto.sha256([0x61, 0x62, 0x63]);
    expect(
      digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  test('AES-256-GCM roundtrip and wrong tag', () async {
    final key = Uint8List(32);
    final iv = Uint8List(12);
    final box = await crypto.aes256gcmEncrypt(key, iv, [1, 2, 3], [4]);
    final plain = await crypto.aes256gcmDecrypt(
      key,
      iv,
      box.ciphertext,
      box.tag,
      [4],
    );
    expect(plain, [1, 2, 3]);
    final bad = Uint8List.fromList(box.tag);
    bad[0] ^= 1;
    expect(
      crypto.aes256gcmDecrypt(key, iv, box.ciphertext, bad, [4]),
      throwsA(isA<CkvfException>()),
    );
  });

  test('Ed25519 sign and verify', () async {
    final pair = await crypto.ed25519Generate();
    final sig = await crypto.ed25519Sign(pair.privateKey, [9]);
    expect(await crypto.ed25519Verify(pair.publicKey, [9], sig), isTrue);
    expect(await crypto.ed25519Verify(pair.publicKey, [8], sig), isFalse);
  });

  test('Argon2id matches the no-secret RFC 9106 inputs', () async {
    // RFC 9106 section 5.3 also passes an 8-byte secret and 12-byte
    // associated data. This interface hashes password and salt only, which
    // is what existing vaults use. Native providers must reproduce this tag.
    final out = await crypto.argon2id(
      password: List<int>.filled(32, 0x01),
      salt: List<int>.filled(16, 0x02),
      m: 32,
      t: 3,
      p: 4,
      keyLength: 32,
    );
    expect(
      out.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e',
    );
  });
}
