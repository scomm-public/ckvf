import { fail } from "./errors.js";

/**
 * Extract a canonical RFC 9580 new-format definite-length Public-Key packet (tag 6)
 * from a Transferable Secret Key or a Public-Key packet.
 */
export function canonicalOpenPgpPublicKey(publicKeyPacket: Uint8Array, tsk?: Uint8Array): Uint8Array {
  const source = publicKeyPacket.length ? publicKeyPacket : tsk;
  if (!source) fail("ERR_ENCODING", "missing OpenPGP key material");
  if (isSinglePublicKeyPacket(source)) return ensureNewFormatTag6(source);
  if (tsk && tsk.length) {
    const extracted = extractPrimaryPublicKey(tsk);
    if (extracted) return extracted;
  }
  if (isSinglePublicKeyPacket(source) === false) {
    const extracted = extractPrimaryPublicKey(source);
    if (extracted) return extracted;
  }
  fail("ERR_ENCODING", "unable to derive canonical OpenPGP Public-Key packet");
}

function extractPrimaryPublicKey(bytes: Uint8Array): Uint8Array | undefined {
  let offset = 0;
  while (offset < bytes.length) {
    const parsed = parsePacket(bytes, offset);
    if (!parsed) break;
    if (parsed.tag === 6) return encodeNewFormatPacket(6, parsed.body);
    if (parsed.tag === 5) return encodeNewFormatPacket(6, publicBodyFromSecret(parsed.body));
    offset = parsed.next;
  }
  return undefined;
}

function isSinglePublicKeyPacket(bytes: Uint8Array): boolean {
  const parsed = parsePacket(bytes, 0);
  return Boolean(parsed && parsed.tag === 6 && parsed.next === bytes.length);
}

function ensureNewFormatTag6(bytes: Uint8Array): Uint8Array {
  const parsed = parsePacket(bytes, 0);
  if (!parsed || parsed.tag !== 6) fail("ERR_ENCODING", "not a Public-Key packet");
  return encodeNewFormatPacket(6, parsed.body);
}

function publicBodyFromSecret(secretBody: Uint8Array): Uint8Array {
  if (secretBody.length < 6) fail("ERR_ENCODING", "truncated Secret-Key packet");
  const version = secretBody[0]!;
  let pos = 0;
  if (version === 4) {
    pos = 1 + 4 + 1;
    const algo = secretBody[5]!;
    pos += publicMaterialLength(secretBody, pos, algo, 4);
    return secretBody.subarray(0, pos);
  }
  if (version === 6) {
    pos = 1 + 4 + 1 + 4;
    const algo = secretBody[5]!;
    const keyOctets = readU32(secretBody, 6);
    if (pos + keyOctets > secretBody.length) fail("ERR_ENCODING", "truncated v6 key");
    void algo;
    return secretBody.subarray(0, pos + keyOctets);
  }
  fail("ERR_ENCODING", `unsupported OpenPGP key version ${version}`);
}

function publicMaterialLength(body: Uint8Array, pos: number, algo: number, version: number): number {
  rejectRfc9980Version(version, algo);
  switch (algo) {
    case 1:
    case 2:
    case 3:
      return mpiLen(body, pos) + mpiLen(body, pos + mpiLen(body, pos));
    case 16:
      return mpiLen(body, pos) + mpiLen(body, pos + mpiLen(body, pos)) + mpiLen(body, pos + mpiLen(body, pos) + mpiLen(body, pos + mpiLen(body, pos)));
    case 17: {
      let p = pos;
      p += mpiLen(body, p);
      p += mpiLen(body, p);
      p += mpiLen(body, p);
      p += mpiLen(body, p);
      return p - pos;
    }
    case 18:
    case 19:
    case 22: {
      const oidLen = body[pos]!;
      let p = pos + 1 + oidLen;
      p += mpiLen(body, p);
      if (algo === 18) {
        const kdfLen = body[p]!;
        p += 1 + kdfLen;
      }
      return p - pos;
    }
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
      fail("ERR_ENCODING", "LibrePGP Kyber is not RFC 9980");
    default:
      fail("ERR_ENCODING", `unsupported OpenPGP algorithm ${algo}`);
  }
}

function rejectRfc9980Version(version: number, algo: number): void {
  if (algo < 30 || algo > 36) return;
  if (algo === 35) {
    if (version === 4 || version === 6) return;
    fail("ERR_ENCODING", "algorithm 35 requires OpenPGP version 4 or 6");
  }
  if (version !== 6) {
    fail("ERR_ENCODING", `RFC 9980 algorithm ${algo} requires OpenPGP version 6`);
  }
}

function mpiLen(body: Uint8Array, pos: number): number {
  if (pos + 2 > body.length) fail("ERR_ENCODING", "truncated MPI");
  const bits = (body[pos]! << 8) | body[pos + 1]!;
  return 2 + Math.ceil(bits / 8);
}

function readU32(body: Uint8Array, pos: number): number {
  return ((body[pos]! << 24) | (body[pos + 1]! << 16) | (body[pos + 2]! << 8) | body[pos + 3]!) >>> 0;
}

interface ParsedPacket {
  tag: number;
  body: Uint8Array;
  next: number;
}

function parsePacket(bytes: Uint8Array, offset: number): ParsedPacket | undefined {
  if (offset >= bytes.length) return undefined;
  const hdr = bytes[offset]!;
  if ((hdr & 0x80) === 0) fail("ERR_ENCODING", "invalid OpenPGP packet header");
  const newFormat = (hdr & 0x40) !== 0;
  if (newFormat) {
    const tag = hdr & 0x3f;
    let pos = offset + 1;
    const [len, lenSize] = readNewLength(bytes, pos);
    pos += lenSize;
    const body = bytes.subarray(pos, pos + len);
    return { tag, body, next: pos + len };
  }
  const tag = (hdr >> 2) & 0x0f;
  const lenType = hdr & 0x03;
  let pos = offset + 1;
  let len: number;
  if (lenType === 0) len = bytes[pos++]!;
  else if (lenType === 1) {
    len = (bytes[pos]! << 8) | bytes[pos + 1]!;
    pos += 2;
  } else if (lenType === 2) {
    len = readU32(bytes, pos);
    pos += 4;
  } else fail("ERR_ENCODING", "indeterminate OpenPGP packet length");
  const body = bytes.subarray(pos, pos + len);
  return { tag, body, next: pos + len };
}

function readNewLength(bytes: Uint8Array, pos: number): [number, number] {
  const o1 = bytes[pos]!;
  if (o1 < 192) return [o1, 1];
  if (o1 < 224) return [(o1 - 192 << 8) + bytes[pos + 1]! + 192, 2];
  if (o1 === 255) return [readU32(bytes, pos + 1), 5];
  fail("ERR_ENCODING", "partial body length not allowed in keys");
}

export function encodeNewFormatPacket(tag: number, body: Uint8Array): Uint8Array {
  const len = body.length;
  let hdr: number[];
  if (len < 192) hdr = [0xc0 | tag, len];
  else if (len < 8384) {
    const d = len - 192;
    hdr = [0xc0 | tag, (d >> 8) + 192, d & 0xff];
  } else hdr = [0xc0 | tag, 255, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
  const out = new Uint8Array(hdr.length + body.length);
  out.set(hdr, 0);
  out.set(body, hdr.length);
  return out;
}

/** Build a minimal RFC 9580 v4 Ed25519 (algo 27) unencrypted Transferable Secret Key. TEST KEYS ONLY. */
export function buildOpenPgpEd25519Tsk(seed: Uint8Array, publicKey: Uint8Array, createdAtUnix: number): Uint8Array {
  if (seed.length !== 32 || publicKey.length !== 32) fail("ERR_ENCODING", "Ed25519 key must be 32 bytes");
  const body = new Uint8Array(1 + 4 + 1 + 32 + 1 + 32 + 2);
  body[0] = 4;
  body[1] = (createdAtUnix >>> 24) & 0xff;
  body[2] = (createdAtUnix >>> 16) & 0xff;
  body[3] = (createdAtUnix >>> 8) & 0xff;
  body[4] = createdAtUnix & 0xff;
  body[5] = 27;
  body.set(publicKey, 6);
  body[38] = 0;
  body.set(seed, 39);
  let sum = 0;
  for (const b of seed) sum = (sum + b) & 0xffff;
  body[71] = (sum >> 8) & 0xff;
  body[72] = sum & 0xff;
  return encodeNewFormatPacket(5, body);
}

export function buildOpenPgpEd25519Public(publicKey: Uint8Array, createdAtUnix: number): Uint8Array {
  const body = new Uint8Array(1 + 4 + 1 + 32);
  body[0] = 4;
  body[1] = (createdAtUnix >>> 24) & 0xff;
  body[2] = (createdAtUnix >>> 16) & 0xff;
  body[3] = (createdAtUnix >>> 8) & 0xff;
  body[4] = createdAtUnix & 0xff;
  body[5] = 27;
  body.set(publicKey, 6);
  return encodeNewFormatPacket(6, body);
}
