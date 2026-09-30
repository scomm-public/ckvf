import 'dart:typed_data';

import 'errors.dart';

Uint8List canonicalOpenPgpPublicKey(
  List<int> publicKeyPacket, [
  List<int>? tsk,
]) {
  final source = publicKeyPacket.isNotEmpty ? publicKeyPacket : tsk;
  if (source == null) fail('ERR_ENCODING', 'missing OpenPGP key material');
  final bytes = Uint8List.fromList(source);
  if (_isSinglePublicKeyPacket(bytes)) return _ensureNewFormatTag6(bytes);
  if (tsk != null && tsk.isNotEmpty) {
    final extracted = _extractPrimaryPublicKey(Uint8List.fromList(tsk));
    if (extracted != null) return extracted;
  }
  final extracted = _extractPrimaryPublicKey(bytes);
  if (extracted != null) return extracted;
  fail('ERR_ENCODING', 'unable to derive canonical OpenPGP Public-Key packet');
}

Uint8List? _extractPrimaryPublicKey(Uint8List bytes) {
  var offset = 0;
  while (offset < bytes.length) {
    final parsed = _parsePacket(bytes, offset);
    if (parsed == null) break;
    if (parsed.tag == 6) return encodeNewFormatPacket(6, parsed.body);
    if (parsed.tag == 5) {
      return encodeNewFormatPacket(6, _publicBodyFromSecret(parsed.body));
    }
    offset = parsed.next;
  }
  return null;
}

bool _isSinglePublicKeyPacket(Uint8List bytes) {
  final parsed = _parsePacket(bytes, 0);
  return parsed != null && parsed.tag == 6 && parsed.next == bytes.length;
}

Uint8List _ensureNewFormatTag6(Uint8List bytes) {
  final parsed = _parsePacket(bytes, 0);
  if (parsed == null || parsed.tag != 6) {
    fail('ERR_ENCODING', 'not a Public-Key packet');
  }
  return encodeNewFormatPacket(6, parsed.body);
}

Uint8List _publicBodyFromSecret(Uint8List secretBody) {
  if (secretBody.length < 6) fail('ERR_ENCODING', 'truncated Secret-Key packet');
  final version = secretBody[0];
  var pos = 0;
  if (version == 4) {
    pos = 1 + 4 + 1;
    final algo = secretBody[5];
    pos += _publicMaterialLength(secretBody, pos, algo, version);
    return secretBody.sublist(0, pos);
  }
  if (version == 6) {
    pos = 1 + 4 + 1 + 4;
    final keyOctets = _readU32(secretBody, 6);
    if (pos + keyOctets > secretBody.length) {
      fail('ERR_ENCODING', 'truncated v6 key');
    }
    return secretBody.sublist(0, pos + keyOctets);
  }
  fail('ERR_ENCODING', 'unsupported OpenPGP key version $version');
}

int _publicMaterialLength(Uint8List body, int pos, int algo, int version) {
  _rejectRfc9980Version(version, algo);
  switch (algo) {
    case 1:
    case 2:
    case 3:
      return _mpiLen(body, pos) + _mpiLen(body, pos + _mpiLen(body, pos));
    case 16:
      final p1 = _mpiLen(body, pos);
      final p2 = _mpiLen(body, pos + p1);
      final p3 = _mpiLen(body, pos + p1 + p2);
      return p1 + p2 + p3;
    case 17:
      var p = pos;
      p += _mpiLen(body, p);
      p += _mpiLen(body, p);
      p += _mpiLen(body, p);
      p += _mpiLen(body, p);
      return p - pos;
    case 18:
    case 19:
    case 22:
      final oidLen = body[pos];
      var p = pos + 1 + oidLen;
      p += _mpiLen(body, p);
      if (algo == 18) {
        final kdfLen = body[p];
        p += 1 + kdfLen;
      }
      return p - pos;
    case 25:
    case 27:
      return 32;
    case 26:
      return 56;
    case 28:
      return 57;
    case 30:
      return 32 + 1952;
    case 31:
      return 57 + 2592;
    case 32:
    case 33:
      return 32;
    case 34:
      return 64;
    case 35:
      return 32 + 1184;
    case 36:
      return 56 + 1568;
    case 105:
    case 106:
      fail('ERR_ENCODING', 'LibrePGP Kyber is not RFC 9980');
    default:
      fail('ERR_ENCODING', 'unsupported OpenPGP algorithm $algo');
  }
}

void _rejectRfc9980Version(int version, int algo) {
  if (algo < 30 || algo > 36) return;
  if (algo == 35) {
    if (version == 4 || version == 6) return;
    fail('ERR_ENCODING', 'algorithm 35 requires OpenPGP version 4 or 6');
  }
  if (version != 6) {
    fail('ERR_ENCODING', 'RFC 9980 algorithm $algo requires OpenPGP version 6');
  }
}

int _mpiLen(Uint8List body, int pos) {
  if (pos + 2 > body.length) fail('ERR_ENCODING', 'truncated MPI');
  final bits = (body[pos] << 8) | body[pos + 1];
  return 2 + (bits + 7) ~/ 8;
}

int _readU32(Uint8List body, int pos) {
  return ((body[pos] << 24) | (body[pos + 1] << 16) | (body[pos + 2] << 8) | body[pos + 3]) &
      0xffffffff;
}

class _ParsedPacket {
  _ParsedPacket({required this.tag, required this.body, required this.next});
  final int tag;
  final Uint8List body;
  final int next;
}

_ParsedPacket? _parsePacket(Uint8List bytes, int offset) {
  if (offset >= bytes.length) return null;
  final hdr = bytes[offset];
  if ((hdr & 0x80) == 0) fail('ERR_ENCODING', 'invalid OpenPGP packet header');
  final newFormat = (hdr & 0x40) != 0;
  if (newFormat) {
    final tag = hdr & 0x3f;
    var pos = offset + 1;
    final lenPair = _readNewLength(bytes, pos);
    pos += lenPair.$2;
    final body = bytes.sublist(pos, pos + lenPair.$1);
    return _ParsedPacket(tag: tag, body: body, next: pos + lenPair.$1);
  }
  final tag = (hdr >> 2) & 0x0f;
  final lenType = hdr & 0x03;
  var pos = offset + 1;
  late int len;
  if (lenType == 0) {
    len = bytes[pos++];
  } else if (lenType == 1) {
    len = (bytes[pos] << 8) | bytes[pos + 1];
    pos += 2;
  } else if (lenType == 2) {
    len = _readU32(bytes, pos);
    pos += 4;
  } else {
    fail('ERR_ENCODING', 'indeterminate OpenPGP packet length');
  }
  final body = bytes.sublist(pos, pos + len);
  return _ParsedPacket(tag: tag, body: body, next: pos + len);
}

(int, int) _readNewLength(Uint8List bytes, int pos) {
  final o1 = bytes[pos];
  if (o1 < 192) return (o1, 1);
  if (o1 < 224) return (((o1 - 192) << 8) + bytes[pos + 1] + 192, 2);
  if (o1 == 255) return (_readU32(bytes, pos + 1), 5);
  fail('ERR_ENCODING', 'partial body length not allowed in keys');
}

Uint8List encodeNewFormatPacket(int tag, List<int> body) {
  final len = body.length;
  late List<int> hdr;
  if (len < 192) {
    hdr = [0xc0 | tag, len];
  } else if (len < 8384) {
    final d = len - 192;
    hdr = [0xc0 | tag, (d >> 8) + 192, d & 0xff];
  } else {
    hdr = [
      0xc0 | tag,
      255,
      (len >> 24) & 0xff,
      (len >> 16) & 0xff,
      (len >> 8) & 0xff,
      len & 0xff,
    ];
  }
  return Uint8List.fromList([...hdr, ...body]);
}

/// Minimal RFC 9580 v4 Ed25519 (algo 27) unencrypted TSK. TEST KEYS ONLY.
Uint8List buildOpenPgpEd25519Tsk(
  List<int> seed,
  List<int> publicKey,
  int createdAtUnix,
) {
  if (seed.length != 32 || publicKey.length != 32) {
    fail('ERR_ENCODING', 'Ed25519 key must be 32 bytes');
  }
  final body = Uint8List(1 + 4 + 1 + 32 + 1 + 32 + 2);
  body[0] = 4;
  body[1] = (createdAtUnix >> 24) & 0xff;
  body[2] = (createdAtUnix >> 16) & 0xff;
  body[3] = (createdAtUnix >> 8) & 0xff;
  body[4] = createdAtUnix & 0xff;
  body[5] = 27;
  body.setRange(6, 38, publicKey);
  body[38] = 0;
  body.setRange(39, 71, seed);
  var sum = 0;
  for (final b in seed) {
    sum = (sum + b) & 0xffff;
  }
  body[71] = (sum >> 8) & 0xff;
  body[72] = sum & 0xff;
  return encodeNewFormatPacket(5, body);
}

Uint8List buildOpenPgpEd25519Public(List<int> publicKey, int createdAtUnix) {
  final body = Uint8List(1 + 4 + 1 + 32);
  body[0] = 4;
  body[1] = (createdAtUnix >> 24) & 0xff;
  body[2] = (createdAtUnix >> 16) & 0xff;
  body[3] = (createdAtUnix >> 8) & 0xff;
  body[4] = createdAtUnix & 0xff;
  body[5] = 27;
  body.setRange(6, 38, publicKey);
  return encodeNewFormatPacket(6, body);
}
