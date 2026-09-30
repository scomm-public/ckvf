import 'errors.dart';
import 'types.dart';

/// Payload extension that records whether a content key's private bytes
/// are in the container. The VEK is unchanged.
const String keyCustodyExtensionId = 'std:key-custody';

const Set<String> _custodyValues = {'portable', 'device-bound', 'external'};

/// Validates `std:key-custody` `data`. Critical entries are device-bound or
/// external. Non-critical entries are portable.
void validateKeyCustodyData(Object? data, {required bool critical}) {
  if (data is! Map) fail('ERR_EXTENSION', 'key custody data');
  final o = Map<String, dynamic>.from(data);
  for (final key in o.keys) {
    if (key != 'absolute_key_id' &&
        key != 'custody' &&
        key != 'provider' &&
        key != 'key_ref') {
      fail('ERR_EXTENSION', 'key custody field $key');
    }
  }
  final id = o['absolute_key_id'];
  if (id is! String || id.isEmpty) {
    fail('ERR_EXTENSION', 'key custody absolute_key_id');
  }
  final custody = o['custody'];
  if (custody is! String || !_custodyValues.contains(custody)) {
    fail('ERR_EXTENSION', 'key custody value');
  }
  final nonExportable = custody == 'device-bound' || custody == 'external';
  if (critical != nonExportable) {
    fail('ERR_EXTENSION', 'key custody critical flag');
  }
  if (nonExportable) {
    final ref = o['key_ref'];
    if (ref is! String || ref.isEmpty) {
      fail('ERR_EXTENSION', 'key custody key_ref');
    }
  }
}

bool isUnderstoodCriticalExtension(Extension extension) {
  return extension.id == keyCustodyExtensionId;
}

/// Key ids whose private bytes must not be copied in from another generation.
Set<String> nonExportableKeyIds(List<Extension> criticalExtensions) {
  final ids = <String>{};
  for (final extension in criticalExtensions) {
    if (extension.id != keyCustodyExtensionId) continue;
    final data = extension.data;
    if (data is! Map) continue;
    final custody = data['custody'];
    if (custody == 'device-bound' || custody == 'external') {
      final id = data['absolute_key_id'];
      if (id is String) ids.add(id);
    }
  }
  return ids;
}

void assertCustodyBindings(Map<String, dynamic> payload) {
  final keys = payload['keys'];
  if (keys is! List) return;
  final byId = <String, Map<String, dynamic>>{};
  for (final raw in keys) {
    if (raw is Map) {
      final id = raw['absolute_key_id'];
      if (id is String) byId[id] = Map<String, dynamic>.from(raw);
    }
  }
  void check(Object? raw) {
    if (raw is! List) return;
    for (final entry in raw) {
      if (entry is! Map) continue;
      if (entry['id'] != keyCustodyExtensionId) continue;
      final data = entry['data'];
      if (data is! Map) continue;
      final id = data['absolute_key_id'];
      final key = id is String ? byId[id] : null;
      if (key == null) fail('ERR_EXTENSION', 'key custody key missing');
      final custody = data['custody'];
      if ((custody == 'device-bound' || custody == 'external') &&
          key['private_key'] != null) {
        fail('ERR_EXTENSION', 'non-exportable key has private bytes');
      }
    }
  }

  check(payload['extensions']);
  check(payload['critical_extensions']);
}
