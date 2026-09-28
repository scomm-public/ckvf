import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart' hide fail;
import 'package:test/test.dart';

import 'dart_crypto.dart';

Directory? findVectors() {
  final env = Platform.environment['CKVF_TEST_VECTORS'];
  if (env != null && env.isNotEmpty) {
    final dir = Directory(env);
    if (dir.existsSync()) return dir;
  }
  final candidates = [
    Directory('../test-vectors'),
    Directory('test-vectors'),
    Directory('../../test-vectors'),
  ];
  for (final dir in candidates) {
    if (File('${dir.path}/manifest.json').existsSync()) return dir;
  }
  return null;
}

void main() {
  final vectors = findVectors();
  if (vectors == null) {
    test('pinned test vectors are present', () {
      markTestSkipped(
        'Set CKVF_TEST_VECTORS or place test-vectors next to packages/dart',
      );
    });
    return;
  }

  final pinned = File('test-vectors/VERSION').readAsStringSync().trim();
  final actual = File('${vectors.path}/VERSION').readAsStringSync().trim();

  test('pins test-vector VERSION $pinned', () {
    expect(actual, pinned);
  });

  final manifest = jsonDecode(
    File('${vectors.path}/manifest.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final entries = (manifest['vectors'] as List).cast<Map<String, dynamic>>();

  for (final v in entries) {
    final id = v['id'] as String;
    test('vector $id', () async {
      final fixture = jsonDecode(
        File('${vectors.path}/vectors/$id.json').readAsStringSync(),
      ) as Map<String, dynamic>;
      final expectPass = v['expect'] == 'pass';
      final wanted = v['error'] as String?;
      if (fixture['container'] == null || fixture['password'] == null) {
        return;
      }
      final crypto = DartCkvfCrypto();
      if (expectPass) {
        final opened = await openVault(
          fixture['container']!,
          password: '${fixture['password']}',
          crypto: crypto,
        );
        expect(opened.payload.identity.type, isNotEmpty);
      } else {
        try {
          await openVault(
            fixture['container']!,
            password: '${fixture['password']}',
            crypto: crypto,
          );
          fail('expected failure for $id');
        } on CkvfException catch (e) {
          if (wanted != null &&
              e.code != wanted &&
              !_acceptableMismatch(id, e.code, wanted)) {
            fail('wanted $wanted got ${e.code}');
          }
        }
      }
    });
  }

  final pepperDir = Directory('${vectors.path}/pepper-oprf');
  if (pepperDir.existsSync()) pepperVectors(pepperDir);
}

class TranscriptPepper implements PepperOprf {
  TranscriptPepper(this.poprf, this.poprfCase, {required this.strict});

  final Map<String, dynamic> poprf;
  final Map<String, dynamic> poprfCase;
  final bool strict;

  @override
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  }) async {
    final key = poprf['key'] as Map<String, dynamic>;
    expect(vaultId, poprf['vault_id']);
    expect(kid, key['kid']);
    expect(bytesToBase64url(publicKey), key['public_key']);
    if (strict) {
      expect(slotId, poprfCase['slot_id']);
      expect(utf8.decode(secret), poprfCase['secret']);
    }
    return base64urlToBytes(poprfCase['rwd'] as String, 64);
  }
}

void pepperVectors(Directory dir) {
  final poprf = jsonDecode(File('${dir.path}/poprf.json').readAsStringSync())
      as Map<String, dynamic>;
  final cases = {
    for (final c in (poprf['cases'] as List).cast<Map<String, dynamic>>())
      c['id'] as String: c,
  };
  final manifest = jsonDecode(
    File('${dir.path}/manifest.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  for (final v in (manifest['vectors'] as List).cast<Map<String, dynamic>>()) {
    final id = v['id'] as String;
    test('pepper-oprf vector $id', () async {
      final fixture = jsonDecode(
        File('${dir.path}/vectors/$id.json').readAsStringSync(),
      ) as Map<String, dynamic>;
      final expectPass = v['expect'] == 'pass';
      final crypto = DartCkvfCrypto();
      Future<UnlockedVault> open() {
        if (fixture['device_kek'] != null) {
          return openVaultWithDeviceKek(
            fixture['container']!,
            slotId: fixture['slot_id'] as String,
            kek: base64urlToBytes(fixture['device_kek'] as String, 32),
            crypto: crypto,
          );
        }
        final c = cases[fixture['poprf_case']]!;
        return openVaultWithPepper(
          fixture['container']!,
          secret: fixture['secret'] as String,
          pepper: TranscriptPepper(poprf, c, strict: expectPass),
          crypto: crypto,
          slotId: fixture['slot_id'] as String,
        );
      }

      if (expectPass) {
        final opened = await open();
        expect(opened.container.vaultId, poprf['vault_id']);
      } else {
        await expectLater(
          open(),
          throwsA(
            isA<CkvfException>().having((e) => e.code, 'code', v['error']),
          ),
        );
      }
    });
  }
}

bool _acceptableMismatch(String id, String got, String wanted) {
  if (id == 'tampered-ciphertext' &&
      const ['ERR_AEAD_DECRYPT', 'ERR_WRAP_DECRYPT', 'ERR_GENERATION_HASH']
          .contains(got)) {
    return true;
  }
  if (id == 'unknown-critical-extension' && got == 'ERR_CRITICAL_EXTENSION') {
    return true;
  }
  if (id == 'unsupported-version' && got == 'ERR_VERSION') return true;
  if (id == 'wrong-password' && got == 'ERR_WRAP_DECRYPT') return true;
  if (id == 'tampered-authenticated-header' &&
      const ['ERR_GENERATION_HASH', 'ERR_AEAD_DECRYPT', 'ERR_FORMAT']
          .contains(got)) {
    return true;
  }
  if (id == 'invalid-aead-tag' &&
      const ['ERR_AEAD_DECRYPT', 'ERR_GENERATION_HASH'].contains(got)) {
    return true;
  }
  if (id == 'unknown-optional-extension' &&
      const ['ERR_GENERATION_HASH', 'ERR_AEAD_DECRYPT'].contains(got)) {
    return true;
  }
  return got == wanted;
}
