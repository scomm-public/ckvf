import 'package:ckvf/ckvf.dart';
import 'package:test/test.dart';

import 'dart_crypto.dart';

void main() {
  final crypto = DartCkvfCrypto();

  test('device-hpke-x25519 round trip', () async {
    final device = await crypto.x25519Generate();
    final vault = await createVault(CreateVaultOptions(
      identityType: 'email',
      identityValue: 'alice@example.com',
      password: 'CKVF-TEST-PASSWORD',
      crypto: crypto,
      kdf: testArgon2id,
      now: '2026-09-29T00:00:00Z',
    ));
    final slot = await wrapDeviceHpkeSlot(
      crypto,
      vaultId: vault.container.vaultId,
      vek: vault.vek,
      recipientPublicKey: device.publicKey,
    );
    final sealed = await commitUnlockSlots(
      vault,
      crypto,
      [...vault.container.unlockSlots, slot],
    );
    final opened = await openVaultWithDeviceHpke(
      serializeContainer(sealed.container),
      slotId: slot.slotId,
      privateKey: device.privateKey,
      crypto: crypto,
    );
    expect(opened.payload.identity.value, 'alice@example.com');
  });

  test('pkcs8 import rejects a public key that is the private key', () async {
    final vault = await createVault(CreateVaultOptions(
      identityType: 'email',
      identityValue: 'alice@example.com',
      password: 'CKVF-TEST-PASSWORD',
      crypto: crypto,
      kdf: testArgon2id,
    ));
    final secret = List<int>.filled(48, 7);
    await expectLater(
      importPrivateKey(
        vault,
        crypto: crypto,
        family: 'smime',
        encoding: 'pkcs8',
        algorithm: 'unknown',
        purpose: const ['encrypt'],
        privateKey: secret,
        publicKey: secret,
      ),
      throwsA(isA<CkvfException>()),
    );
  });
}
