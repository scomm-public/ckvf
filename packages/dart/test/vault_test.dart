import 'package:ckvf/ckvf.dart';
import 'package:test/test.dart';

import 'dart_crypto.dart';

const password = 'CKVF-TEST-PASSWORD';
const now = '2026-08-17T00:00:00Z';

void main() {
  test('create, inspect, open empty vault', () async {
    final crypto = DartCkvfCrypto();
    final created = await createVault(
      CreateVaultOptions(
        identityType: 'email',
        identityValue: 'Alice@Example.COM',
        password: password,
        crypto: crypto,
        now: now,
        kdf: testArgon2id,
      ),
    );
    expect(created.payload.identity.value, 'alice@example.com');
    expect(created.container.generation, 1);
    expect(created.container.previousGenerationHash, isNull);
    final json = serializeContainer(created.container);
    final meta = inspectPublicMetadata(json);
    expect(meta['format'], 'CKVF');
    expect(jsonEncodeMeta(meta), isNot(contains('alice@example.com')));
    final opened = await openVault(json, password: password, crypto: crypto);
    expect(opened.payload.keys, isEmpty);
    expect(
      opened.payload.identity.identityId,
      created.payload.identity.identityId,
    );
  });

  test('wrong password fails closed', () async {
    final crypto = DartCkvfCrypto();
    final created = await createVault(
      CreateVaultOptions(
        identityType: 'email',
        identityValue: 'alice@example.com',
        password: password,
        crypto: crypto,
        now: now,
        kdf: testArgon2id,
      ),
    );
    expect(
      () => openVault(created.container, password: 'wrong', crypto: crypto),
      throwsA(
        isA<CkvfException>().having((e) => e.code, 'code', 'ERR_WRAP_DECRYPT'),
      ),
    );
  });

  test('OpenPGP and PKCS#8 keys plus historical retire', () async {
    final crypto = DartCkvfCrypto();
    var vault = await createVault(
      CreateVaultOptions(
        identityType: 'email',
        identityValue: 'alice@example.com',
        password: password,
        crypto: crypto,
        now: now,
        kdf: testArgon2id,
      ),
    );
    vault = await addTestOpenPgpKey(vault, crypto, now);
    vault = await addTestPkcs8Key(vault, crypto, now);
    expect(vault.payload.keys, hasLength(2));
    final pgp = vault.payload.keys.firstWhere((k) => k.family == 'openpgp');
    final smime = vault.payload.keys.firstWhere((k) => k.family == 'smime');
    expect(exportPrivateKey(vault, pgp.absoluteKeyId), isNotEmpty);
    expect(exportPrivateKey(vault, smime.absoluteKeyId), isNotEmpty);
    vault = await retireKey(vault, crypto, pgp.absoluteKeyId, now);
    expect(
      vault.payload.keys.firstWhere((k) => k.absoluteKeyId == pgp.absoluteKeyId).status,
      'retired',
    );
    final reopened = await openVault(
      serializeContainer(vault.container),
      password: password,
      crypto: crypto,
    );
    expect(reopened.payload.keys, hasLength(2));
  });

  test('Ckvf facade create/decrypt roundtrip', () async {
    final crypto = DartCkvfCrypto();
    final unlocked = await Ckvf.create(
      identity: {'type': 'email', 'value': 'bob@example.com'},
      password: password,
      crypto: crypto,
      now: now,
    );
    final locked = await Ckvf.encrypt(unlocked: unlocked, crypto: crypto);
    final opened = await Ckvf.decrypt(
      container: locked,
      password: password,
      crypto: crypto,
    );
    expect(opened.payload.identity.value, 'bob@example.com');
  });
}

String jsonEncodeMeta(Map<String, dynamic> meta) => meta.toString();
