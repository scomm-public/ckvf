import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import 'crypto_provider.dart';
import 'errors.dart';

/// Software Dart provider (package:cryptography). Not hardware-backed.
class DartCkvfCrypto implements CkvfCrypto {
  DartCkvfCrypto();

  final Ed25519 _ed25519 = Ed25519();
  final AesGcm _aesGcm = AesGcm.with256bits();
  final Random _random = Random.secure();

  @override
  Uint8List randomBytes(int n) {
    return Uint8List.fromList(List<int>.generate(n, (_) => _random.nextInt(256)));
  }

  @override
  Future<Uint8List> sha256(List<int> data) async {
    return Uint8List.fromList(crypto.sha256.convert(data).bytes);
  }

  @override
  Future<({Uint8List ciphertext, Uint8List tag})> aes256gcmEncrypt(
    List<int> key,
    List<int> iv,
    List<int> plaintext,
    List<int> aad,
  ) async {
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: iv,
      aad: aad,
    );
    return (
      ciphertext: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    );
  }

  @override
  Future<Uint8List> aes256gcmDecrypt(
    List<int> key,
    List<int> iv,
    List<int> ciphertext,
    List<int> tag,
    List<int> aad,
  ) async {
    try {
      final plain = await _aesGcm.decrypt(
        SecretBox(ciphertext, nonce: iv, mac: Mac(tag)),
        secretKey: SecretKey(key),
        aad: aad,
      );
      return Uint8List.fromList(plain);
    } catch (_) {
      fail('ERR_AEAD_DECRYPT');
    }
  }

  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) async {
    final algorithm = Argon2id(
      parallelism: p,
      memory: m,
      iterations: t,
      hashLength: keyLength,
    );
    final key = await algorithm.deriveKey(
      secretKey: SecretKey(password),
      nonce: salt,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519Generate() async {
    final pair = await _ed25519.newKeyPair();
    final privateKey = Uint8List.fromList(await pair.extractPrivateKeyBytes());
    final public = await pair.extractPublicKey();
    return (
      publicKey: Uint8List.fromList(public.bytes),
      privateKey: privateKey,
    );
  }

  @override
  Future<Uint8List> ed25519PublicFromSeed(List<int> seed) async {
    final pair = await _ed25519.newKeyPairFromSeed(seed);
    final public = await pair.extractPublicKey();
    return Uint8List.fromList(public.bytes);
  }

  @override
  Future<Uint8List> ed25519Sign(List<int> seed, List<int> message) async {
    final pair = await _ed25519.newKeyPairFromSeed(seed);
    final signature = await _ed25519.sign(message, keyPair: pair);
    return Uint8List.fromList(signature.bytes);
  }

  @override
  Future<bool> ed25519Verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) {
    return _ed25519.verify(
      message,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      ),
    );
  }
}

final defaultCkvfCrypto = DartCkvfCrypto();
