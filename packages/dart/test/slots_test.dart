import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:crypto/crypto.dart' as hash;
import 'package:test/test.dart';

import 'dart_crypto.dart';

const password = 'CKVF-TEST-PASSWORD';
const now = '2026-09-27T00:00:00Z';

/// Stands in for the host: rwd depends on a per-kid server key, so a client
/// holding only the password cannot compute it.
class FakePepperHost implements PepperOprf {
  FakePepperHost(this.serverKeys);

  final Map<String, List<int>> serverKeys;
  var calls = 0;

  @override
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  }) async {
    calls++;
    final key = serverKeys[kid];
    if (key == null) throw StateError('unknown kid');
    return Uint8List.fromList(
      hash.sha512.convert([
        ...key,
        ...vaultId.codeUnits,
        0,
        ...slotId.codeUnits,
        0,
        ...secret
      ]).bytes,
    );
  }
}

/// Real crypto, but Argon2id runs at the test floor whatever the slot says.
class FastKdfCrypto implements CkvfCrypto {
  final _inner = DartCkvfCrypto();

  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) =>
      _inner.argon2id(
        password: password,
        salt: salt,
        m: testArgon2id.m,
        t: testArgon2id.t,
        p: testArgon2id.p,
        keyLength: keyLength,
      );

  @override
  Uint8List randomBytes(int n) => _inner.randomBytes(n);
  @override
  Future<Uint8List> sha256(List<int> data) => _inner.sha256(data);
  @override
  Future<({Uint8List ciphertext, Uint8List tag})> aes256gcmEncrypt(
    List<int> key,
    List<int> iv,
    List<int> plaintext,
    List<int> aad,
  ) =>
      _inner.aes256gcmEncrypt(key, iv, plaintext, aad);
  @override
  Future<Uint8List> aes256gcmDecrypt(
    List<int> key,
    List<int> iv,
    List<int> ciphertext,
    List<int> tag,
    List<int> aad,
  ) =>
      _inner.aes256gcmDecrypt(key, iv, ciphertext, tag, aad);
  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519Generate() =>
      _inner.ed25519Generate();
  @override
  Future<Uint8List> ed25519PublicFromSeed(List<int> seed) =>
      _inner.ed25519PublicFromSeed(seed);
  @override
  Future<Uint8List> ed25519Sign(List<int> seed, List<int> message) =>
      _inner.ed25519Sign(seed, message);
  @override
  Future<bool> ed25519Verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) =>
      _inner.ed25519Verify(publicKey, message, signature);
}

final key1 =
    PepperKey(kid: 'k1', publicKey: Uint8List(32)..fillRange(0, 32, 1));
final key2 =
    PepperKey(kid: 'k2', publicKey: Uint8List(32)..fillRange(0, 32, 2));

Matcher throwsCode(String code) =>
    throwsA(isA<CkvfException>().having((e) => e.code, 'code', code));

Future<UnlockedVault> newVault(CkvfCrypto crypto) => createVault(
      CreateVaultOptions(
        identityType: 'email',
        identityValue: 'alice@example.com',
        password: password,
        crypto: crypto,
        now: now,
        kdf: testArgon2id,
      ),
    );

void main() {
  final crypto = FastKdfCrypto();
  final host = FakePepperHost({
    'k1': List.filled(32, 0x11),
    'k2': List.filled(32, 0x22),
  });

  test('pepper password slot opens only through the host', () async {
    var vault = await newVault(crypto);
    vault = await addPepperSlot(
      vault,
      crypto,
      method: passwordOprfMethod,
      secret: 'pepper pass',
      pepper: host,
      key: key1,
      now: now,
    );
    final json = serializeContainer(vault.container);
    final slot = vault.container.unlockSlots.last;
    expect(slot.method, passwordOprfMethod);
    expect(slot.oprf!.kid, 'k1');
    expect(slot.kdf!.m, greaterThanOrEqualTo(65536));
    expect(slot.kdf!.t, greaterThanOrEqualTo(3));

    final opened = await openVaultWithPepper(
      json,
      secret: 'pepper pass',
      pepper: host,
      crypto: crypto,
    );
    expect(
        opened.payload.identity.identityId, vault.payload.identity.identityId);

    await expectLater(
      openVaultWithPepper(json, secret: 'wrong', pepper: host, crypto: crypto),
      throwsCode('ERR_WRAP_DECRYPT'),
    );
  });

  test('no unwrap without the host pepper key', () async {
    var vault = await newVault(crypto);
    vault = await addPepperSlot(
      vault,
      crypto,
      method: passwordOprfMethod,
      secret: 'pepper pass',
      pepper: host,
      key: key1,
      now: now,
    );
    final json = serializeContainer(vault.container);
    final attacker = FakePepperHost({'k1': List.filled(32, 0x99)});
    await expectLater(
      openVaultWithPepper(
        json,
        secret: 'pepper pass',
        pepper: attacker,
        crypto: crypto,
      ),
      throwsCode('ERR_WRAP_DECRYPT'),
    );
    await expectLater(
      openVaultWithPepper(
        json,
        secret: 'pepper pass',
        pepper: FakePepperHost({}),
        crypto: crypto,
      ),
      throwsA(isA<StateError>()),
    );
  });

  test('pepper slots reject Argon2id below the pepper floor', () async {
    final vault = await newVault(crypto);
    await expectLater(
      addPepperSlot(
        vault,
        crypto,
        method: passwordOprfMethod,
        secret: 'x',
        pepper: host,
        key: key1,
        kdf: testArgon2id,
      ),
      throwsCode('ERR_KDF'),
    );
  });

  test('kid rotation rewraps in place and merge keeps the newer slot',
      () async {
    var vault = await newVault(crypto);
    vault = await addPepperSlot(
      vault,
      crypto,
      method: passwordOprfMethod,
      secret: 'pepper pass',
      pepper: host,
      key: key1,
      now: now,
    );
    final stale = vault;
    final slotId = vault.container.unlockSlots.last.slotId;
    final rotated = await rewrapPepperSlot(
      vault,
      crypto,
      slotId: slotId,
      secret: 'pepper pass',
      pepper: host,
      key: key2,
      now: now,
    );
    expect(rotated.container.generation, stale.container.generation + 1);
    final slot = rotated.container.unlockSlots.last;
    expect(slot.slotId, slotId);
    expect(slot.oprf!.kid, 'k2');
    expect(rotated.container.unlockSlots,
        hasLength(stale.container.unlockSlots.length));

    final json = serializeContainer(rotated.container);
    final opened = await openVaultWithPepper(
      json,
      secret: 'pepper pass',
      pepper: FakePepperHost({'k2': List.filled(32, 0x22)}),
      crypto: crypto,
      slotId: slotId,
    );
    expect(opened.vek, rotated.vek);
    await expectLater(
      openVaultWithPepper(
        json,
        secret: 'pepper pass',
        pepper: FakePepperHost({'k1': List.filled(32, 0x11)}),
        crypto: crypto,
      ),
      throwsA(isA<StateError>()),
    );

    final merged = await mergeVaults(stale, rotated, crypto, now);
    expect(
      merged.container.unlockSlots
          .firstWhere((s) => s.slotId == slotId)
          .oprf!
          .kid,
      'k2',
    );
  });

  test('recovery code slot accepts display formatting', () async {
    final code = generateRecoveryCode(crypto);
    expect(code, matches(RegExp(r'^[A-Z2-7]{5}(-[A-Z2-7]{1,5}){5}$')));
    expect(canonicalRecoveryCode(code), hasLength(26));
    expect(() => canonicalRecoveryCode('short'), throwsCode('ERR_UNLOCK'));

    var vault = await newVault(crypto);
    vault = await addPepperSlot(
      vault,
      crypto,
      method: recoveryCodeOprfMethod,
      secret: code,
      pepper: host,
      key: key1,
      now: now,
    );
    final opened = await openVaultWithPepper(
      serializeContainer(vault.container),
      secret: code.replaceAll('-', ' ').toLowerCase(),
      pepper: host,
      crypto: crypto,
      method: recoveryCodeOprfMethod,
    );
    expect(opened.vek, vault.vek);
  });

  test('device slot opens offline with its KEK', () async {
    final kek = crypto.randomBytes(32);
    var vault = await newVault(crypto);
    vault = await addDeviceSlot(vault, crypto, kek: kek, now: now);
    final slot = vault.container.unlockSlots.last;
    expect(slot.method, deviceWrapMethod);
    expect(slot.kdf, isNull);
    final json = serializeContainer(vault.container);
    final opened = await openVaultWithDeviceKek(
      json,
      slotId: slot.slotId,
      kek: kek,
      crypto: crypto,
    );
    expect(opened.vek, vault.vek);
    await expectLater(
      openVaultWithDeviceKek(
        json,
        slotId: slot.slotId,
        kek: crypto.randomBytes(32),
        crypto: crypto,
      ),
      throwsCode('ERR_WRAP_DECRYPT'),
    );
    expect(
      await openVault(json, password: password, crypto: crypto),
      isA<UnlockedVault>(),
    );
  });

  test('password open ignores pepper slots', () async {
    var vault = await newVault(crypto);
    vault = await addPepperSlot(
      vault,
      crypto,
      method: passwordOprfMethod,
      secret: password,
      pepper: host,
      key: key1,
      now: now,
    );
    host.calls = 0;
    final opened = await openVault(
      serializeContainer(vault.container),
      password: password,
      crypto: crypto,
    );
    expect(opened.vek, vault.vek);
    expect(host.calls, 0);
  });
}
