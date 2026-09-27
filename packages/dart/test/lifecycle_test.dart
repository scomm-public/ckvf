import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:test/test.dart';

void main() {
  final crypto = DartCkvfCrypto();
  final kek = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
  final seed = Uint8List.fromList(List<int>.generate(32, (i) => 200 - i));

  Future<UnlockedVault> deviceVault() => createVault(
        CreateVaultOptions(
          identityType: 'email',
          identityValue: 'alice@example.com',
          crypto: crypto,
          mskSeed: seed,
          slots: (vaultId, vek) async => [
            await wrapDeviceSlot(
              crypto,
              vaultId: vaultId,
              vek: vek,
              kek: kek,
              slotId: 'AAAAAAAAAAAAAAAAAAAAAA',
            ),
          ],
          extensions: [
            Extension(id: 'priv:scomm.keys', critical: false, data: {}),
          ],
        ),
      );

  Future<UnlockedVault> reopen(UnlockedVault v) => openVaultWithDeviceKek(
        serializeContainer(v.container),
        slotId: 'AAAAAAAAAAAAAAAAAAAAAA',
        kek: kek,
        crypto: crypto,
      );

  test('creates generation 1 with an existing MSK and only a device slot',
      () async {
    final v = await deviceVault();
    expect(v.container.generation, 1);
    expect(v.container.previousGenerationHash, isNull);
    expect(v.container.unlockSlots.map((s) => s.method), [deviceWrapMethod]);
    expect(v.payload.msk.current.privateKey, bytesToBase64url(seed));
    expect(
      v.payload.msk.current.publicKey,
      bytesToBase64url(await crypto.ed25519PublicFromSeed(seed)),
    );
    final opened = await reopen(v);
    expect(opened.payload.extensions.single.id, 'priv:scomm.keys');
  });

  test('refuses a vault without any slot', () {
    expect(
      () => createVault(
        CreateVaultOptions(
          identityType: 'email',
          identityValue: 'alice@example.com',
          crypto: crypto,
        ),
      ),
      throwsA(isA<CkvfException>()),
    );
  });

  test('DELETE_PRIVATE_KEY clears the private key and appends a tombstone',
      () async {
    var v = await addTestOpenPgpKey(await deviceVault(), crypto);
    final id = v.payload.keys.single.absoluteKeyId;
    v = await deletePrivateKey(v, crypto, id);
    final key = getKey(v, id)!;
    expect(key.privateKey, isNull);
    expect(key.status, 'retired');
    expect(v.payload.tombstones.single.reason, 'policy');
    expect(v.container.generation, 3);
    await reopen(v);
  });

  test('preferred key must be an active key of that family and purpose',
      () async {
    var v = await addTestOpenPgpKey(await deviceVault(), crypto);
    final id = v.payload.keys.single.absoluteKeyId;
    v = await setPreferredKey(v, crypto,
        family: 'openpgp', purpose: 'encrypt', absoluteKeyId: id);
    expect(v.payload.preferredKeys['openpgp']!['encrypt'], id);
    expect(
      () => setPreferredKey(v, crypto,
          family: 'smime', purpose: 'encrypt', absoluteKeyId: id),
      throwsA(isA<CkvfException>()),
    );
    v = await revokeKey(v, crypto, id);
    expect(getKey(v, id)!.privateKey, isNotNull);
    v = await setPreferredKey(v, crypto, family: 'openpgp', purpose: 'encrypt');
    expect(v.payload.preferredKeys, isEmpty);
  });

  test('rotateVek replaces the VEK and the slots', () async {
    final v = await deviceVault();
    final newKek = Uint8List.fromList(List<int>.filled(32, 9));
    final rotated = await rotateVek(
      v,
      crypto,
      (vaultId, vek) async => [
        await wrapDeviceSlot(crypto,
            vaultId: vaultId,
            vek: vek,
            kek: newKek,
            slotId: 'BBBBBBBBBBBBBBBBBBBBBA'),
      ],
    );
    expect(rotated.vek, isNot(v.vek));
    expect(
        rotated.container.previousGenerationHash, v.container.generationHash);
    await expectLater(reopen(rotated), throwsA(isA<CkvfException>()));
    final opened = await openVaultWithDeviceKek(
      serializeContainer(rotated.container),
      slotId: 'BBBBBBBBBBBBBBBBBBBBBA',
      kek: newKek,
      crypto: crypto,
    );
    expect(opened.payload.msk.current.mskId, v.payload.msk.current.mskId);
  });

  test('mergeOnto seals head + 1 however far the local copy advanced',
      () async {
    final base = await deviceVault();
    final head = await addTestOpenPgpKey(base, crypto);
    var local = await addTestPkcs8Key(base, crypto);
    local = await addTestOpenPgpKey(local, crypto);
    expect(local.container.generation, 3);

    final merged = await mergeOnto(head, local, crypto);
    expect(merged.vault.container.generation, 3);
    expect(
      merged.vault.container.previousGenerationHash,
      head.container.generationHash,
    );
    expect(merged.vault.payload.keys, hasLength(3));
    expect(merged.conflicts, isEmpty);
    await Ckvf.validate(merged.vault.container);
    await reopen(merged.vault);
  });

  test('rechain restarts a local chain at generation 1', () async {
    var v = await addTestOpenPgpKey(await deviceVault(), crypto);
    v = await addTestPkcs8Key(v, crypto);
    final genesis = await rechain(v, crypto,
        generation: 1, previousGenerationHash: null);
    expect(genesis.container.generation, 1);
    expect(genesis.container.previousGenerationHash, isNull);
    expect(genesis.container.crypto.iv, isNot(v.container.crypto.iv));
    expect((await reopen(genesis)).payload.keys, hasLength(2));
    expect(
      () => rechain(v, crypto, generation: 2, previousGenerationHash: null),
      throwsA(isA<CkvfException>()),
    );
  });

  test('slot changes never reuse the payload IV', () async {
    final v = await deviceVault();
    final next = await addUnlockSlot(v, crypto, 'correct horse');
    expect(next.container.crypto.iv, isNot(v.container.crypto.iv));
  });
}
