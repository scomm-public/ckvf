// Builds test-vectors/pepper-oprf/{manifest.json,vectors/*.json} from the
// POPRF transcripts in test-vectors/pepper-oprf/poprf.json (written by
// packages/js/packages/node/src/generate-pepper-vectors.ts).
//
//   dart run tool/pepper_vectors.dart [path/to/test-vectors]
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';

const now = '2026-09-27T00:00:00Z';
const password = 'CKVF-TEST-PASSWORD';
const pepperKdf = Argon2idParams(m: 65536, t: 3, p: 1);

class VectorPepper implements PepperOprf {
  VectorPepper(this.rwd);

  final Uint8List rwd;

  @override
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  }) async =>
      rwd;
}

Future<void> main(List<String> args) async {
  final root = Directory(args.isNotEmpty ? args.first : '../../test-vectors');
  final dir = Directory('${root.path}/pepper-oprf');
  final poprf = jsonDecode(File('${dir.path}/poprf.json').readAsStringSync())
      as Map<String, dynamic>;
  final key = poprf['key'] as Map<String, dynamic>;
  final pepperKey = PepperKey(
    kid: key['kid'] as String,
    publicKey: base64urlToBytes(key['public_key'] as String, 32),
  );
  final vaultId = poprf['vault_id'] as String;
  final cases = {
    for (final c in (poprf['cases'] as List).cast<Map<String, dynamic>>())
      c['id'] as String: c,
  };
  final crypto = DartCkvfCrypto();

  Future<UnlockedVault> base() => createVault(
        CreateVaultOptions(
          identityType: 'email',
          identityValue: 'alice@example.com',
          password: password,
          crypto: crypto,
          now: now,
          kdf: testArgon2id,
          vaultId: vaultId,
        ),
      );

  Future<Map<String, dynamic>> pepperContainer(Map<String, dynamic> c) async {
    final vault = await addPepperSlot(
      await base(),
      crypto,
      method: c['method'] as String,
      secret: c['secret'] as String,
      pepper: VectorPepper(base64urlToBytes(c['rwd'] as String, 64)),
      key: pepperKey,
      kdf: pepperKdf,
      slotId: c['slot_id'] as String,
      now: now,
    );
    return jsonDecode(serializeContainer(vault.container))
        as Map<String, dynamic>;
  }

  final pw = cases['password-oprf-unlock']!;
  final rc = cases['recovery-code-oprf-unlock']!;
  final pwContainer = await pepperContainer(pw);
  final rcContainer = await pepperContainer(rc);

  final deviceKek =
      Uint8List.fromList(List.generate(32, (i) => 0xd0 + i & 0xff));
  final deviceSlotId = bytesToBase64url(
    Uint8List.fromList(List.generate(16, (i) => 0xc0 + i)),
  );
  final deviceVault = await addDeviceSlot(
    await base(),
    crypto,
    kek: deviceKek,
    slotId: deviceSlotId,
    now: now,
  );
  final deviceContainer = jsonDecode(serializeContainer(deviceVault.container))
      as Map<String, dynamic>;

  Map<String, dynamic> mutateSlot(
    Map<String, dynamic> container,
    String slotId,
    void Function(Map<String, dynamic> slot) edit,
  ) {
    final copy = jsonDecode(jsonEncode(container)) as Map<String, dynamic>;
    for (final s
        in (copy['unlock_slots'] as List).cast<Map<String, dynamic>>()) {
      if (s['slot_id'] == slotId) edit(s);
    }
    return copy;
  }

  final vectors = <Map<String, dynamic>>[
    {
      'id': 'password-oprf-unlock',
      'expect': 'pass',
      'error': null,
      'container': pwContainer,
      'slot_id': pw['slot_id'],
      'secret': pw['secret'],
      'poprf_case': 'password-oprf-unlock',
    },
    {
      'id': 'recovery-code-oprf-unlock',
      'expect': 'pass',
      'error': null,
      'container': rcContainer,
      'slot_id': rc['slot_id'],
      'secret': 'abcde-fghij klmno-pqrst-uvwxy-z',
      'poprf_case': 'recovery-code-oprf-unlock',
    },
    {
      'id': 'pepper-wrong-rwd',
      'expect': 'fail',
      'error': 'ERR_WRAP_DECRYPT',
      'container': pwContainer,
      'slot_id': pw['slot_id'],
      'secret': pw['secret'],
      'poprf_case': 'recovery-code-oprf-unlock',
    },
    {
      'id': 'pepper-kdf-below-floor',
      'expect': 'fail',
      'error': 'ERR_KDF',
      'container': mutateSlot(pwContainer, pw['slot_id'] as String, (s) {
        (s['kdf'] as Map<String, dynamic>)['m'] = 16384;
      }),
      'slot_id': pw['slot_id'],
      'secret': pw['secret'],
      'poprf_case': 'password-oprf-unlock',
    },
    {
      'id': 'pepper-missing-oprf',
      'expect': 'fail',
      'error': 'ERR_FORMAT',
      'container': mutateSlot(
        pwContainer,
        pw['slot_id'] as String,
        (s) => s.remove('oprf'),
      ),
      'slot_id': pw['slot_id'],
      'secret': pw['secret'],
      'poprf_case': 'password-oprf-unlock',
    },
    {
      'id': 'device-wrap-unlock',
      'expect': 'pass',
      'error': null,
      'container': deviceContainer,
      'slot_id': deviceSlotId,
      'device_kek': bytesToBase64url(deviceKek),
    },
    {
      'id': 'device-wrap-with-kdf',
      'expect': 'fail',
      'error': 'ERR_KDF',
      'container': mutateSlot(deviceContainer, deviceSlotId, (s) {
        s['kdf'] = pwContainer['unlock_slots'][0]['kdf'];
      }),
      'slot_id': deviceSlotId,
      'device_kek': bytesToBase64url(deviceKek),
    },
  ];

  final out = Directory('${dir.path}/vectors')..createSync(recursive: true);
  const encoder = JsonEncoder.withIndent('  ');
  for (final v in vectors) {
    File('${out.path}/${v['id']}.json')
        .writeAsStringSync('${encoder.convert(v)}\n');
  }
  File('${dir.path}/manifest.json').writeAsStringSync(
    '${encoder.convert({
          'version': '0.1.0',
          'profile': 'profiles/pepper-oprf.md',
          'banner': 'TEST KEY — NEVER USE IN PRODUCTION',
          'poprf': 'poprf.json',
          'vectors': [
            for (final v in vectors)
              {'id': v['id'], 'expect': v['expect'], 'error': v['error']},
          ],
        })}\n',
  );
  stdout.writeln('wrote ${vectors.length} vectors to ${out.path}');
}
