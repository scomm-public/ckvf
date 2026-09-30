import { assertCustodyBindings, KEY_CUSTODY_EXTENSION_ID, validateKeyCustodyData } from "./custody.js";
import { fail } from "./errors.js";
import { DEFAULT_LIMITS, type ParserLimits } from "./limits.js";
import { base64urlToBytes } from "./base64url.js";
import { isForbiddenFamily, ALGORITHM_SUITES, KEY_ENCODINGS, KEY_FAMILIES, KEY_PURPOSES, KEY_STATUSES } from "./registries.js";
import { canReadVersion } from "./version.js";
import { CKVF_FORMAT } from "./types.js";
import type {
  Extension,
  KeyRecord,
  UnlockSlot,
  VaultContainer,
  VaultPayload,
} from "./types.js";

export function parseJsonLimited(text: string, limits: ParserLimits = DEFAULT_LIMITS): unknown {
  if (text.length > limits.maxVaultBytes) fail("ERR_PARSER_LIMIT", "vault JSON too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("ERR_JSON", "invalid JSON");
  }
  assertNesting(parsed, 0, limits.maxJsonNesting);
  return parsed;
}

function assertNesting(value: unknown, depth: number, max: number): void {
  if (depth > max) fail("ERR_PARSER_LIMIT", "JSON nesting");
  if (value && typeof value === "object") {
    const vals = Array.isArray(value) ? value : Object.values(value);
    for (const v of vals) assertNesting(v, depth + 1, max);
  }
}

export function validateContainerShape(raw: unknown, limits: ParserLimits = DEFAULT_LIMITS): VaultContainer {
  if (!raw || typeof raw !== "object") fail("ERR_JSON", "container is not an object");
  const o = raw as Record<string, unknown>;
  rejectUnknownKeys(o, [
    "format",
    "version",
    "vault_id",
    "generation",
    "previous_generation_hash",
    "generation_hash",
    "crypto",
    "unlock_slots",
    "ciphertext",
    "tag",
    "extensions",
    "critical_extensions",
  ]);
  if (o.format !== CKVF_FORMAT) fail("ERR_FORMAT", "format must be CKVF");
  if (typeof o.version !== "string" || !canReadVersion(o.version)) fail("ERR_VERSION", `unsupported version ${String(o.version)}`);
  if (typeof o.vault_id !== "string") fail("ERR_FORMAT", "vault_id");
  base64urlToBytes(o.vault_id, 16);
  if (typeof o.generation !== "number" || !Number.isInteger(o.generation) || o.generation < 1) {
    fail("ERR_FORMAT", "generation");
  }
  if (o.generation === 1) {
    if (o.previous_generation_hash !== null) fail("ERR_FORMAT", "generation 1 previous_generation_hash must be null");
  } else if (typeof o.previous_generation_hash !== "string") {
    fail("ERR_FORMAT", "previous_generation_hash");
  } else {
    base64urlToBytes(o.previous_generation_hash, 32);
  }
  if (typeof o.generation_hash !== "string") fail("ERR_FORMAT", "generation_hash");
  base64urlToBytes(o.generation_hash, 32);
  if (!o.crypto || typeof o.crypto !== "object") fail("ERR_FORMAT", "crypto");
  const crypto = o.crypto as Record<string, unknown>;
  rejectUnknownKeys(crypto, ["aead", "iv"]);
  if (crypto.aead !== "A256GCM") fail("ERR_NOT_IMPLEMENTED", "only A256GCM is mandatory in v1.0");
  if (typeof crypto.iv !== "string") fail("ERR_FORMAT", "iv");
  base64urlToBytes(crypto.iv, 12);
  if (!Array.isArray(o.unlock_slots)) fail("ERR_FORMAT", "unlock_slots");
  if (o.unlock_slots.length > limits.maxUnlockSlots) fail("ERR_PARSER_LIMIT", "too many unlock slots");
  const slots = (o.unlock_slots as unknown[]).map((s) => validateUnlockSlot(s, limits));
  const ids = new Set<string>();
  for (const s of slots) {
    if (ids.has(s.slot_id)) fail("ERR_SLOT_ID", "duplicate slot_id");
    ids.add(s.slot_id);
  }
  if (typeof o.ciphertext !== "string") fail("ERR_FORMAT", "ciphertext");
  const ct = base64urlToBytes(o.ciphertext);
  if (ct.length > limits.maxPayloadBytes) fail("ERR_PARSER_LIMIT", "ciphertext too large");
  if (typeof o.tag !== "string") fail("ERR_FORMAT", "tag");
  base64urlToBytes(o.tag, 16);
  const extensions = validateExtensions(o.extensions, false, limits);
  const critical = validateExtensions(o.critical_extensions, true, limits);
  return o as unknown as VaultContainer;
}

export function validateUnlockSlot(raw: unknown, limits: ParserLimits = DEFAULT_LIMITS): UnlockSlot {
  if (!raw || typeof raw !== "object") fail("ERR_FORMAT", "unlock slot");
  const o = raw as Record<string, unknown>;
  rejectUnknownKeys(o, ["slot_id", "method", "created_at", "kdf", "wrap"]);
  if (typeof o.slot_id !== "string") fail("ERR_SLOT_ID", "slot_id");
  base64urlToBytes(o.slot_id, 16);
  if (o.method !== "password-argon2id" && o.method !== "device-wrap-a256gcm") {
    fail("ERR_NOT_IMPLEMENTED", `unlock method ${String(o.method)}`);
  }
  if (typeof o.created_at !== "string" || !isRfc3339Z(o.created_at)) fail("ERR_FORMAT", "created_at");
  if (o.method === "password-argon2id") {
    if (!o.kdf || typeof o.kdf !== "object") fail("ERR_KDF", "missing kdf");
    const k = o.kdf as Record<string, unknown>;
    rejectUnknownKeys(k, ["alg", "salt", "m", "t", "p", "key_length"]);
    if (k.alg !== "Argon2id") fail("ERR_KDF", "alg");
    if (typeof k.salt !== "string") fail("ERR_KDF", "salt");
    const salt = base64urlToBytes(k.salt);
    if (salt.length < 16) fail("ERR_KDF", "salt too short");
    if (typeof k.m !== "number" || typeof k.t !== "number" || typeof k.p !== "number") fail("ERR_KDF");
    if (k.key_length !== 32) fail("ERR_KDF", "key_length");
    if (k.m < limits.minArgon2MemoryKiB || k.t < limits.minArgon2Time || k.p < limits.minArgon2Parallelism) {
      fail("ERR_KDF", "unsafe Argon2id parameters");
    }
    if (k.m > limits.maxArgon2MemoryKiB || k.t > limits.maxArgon2Time || k.p > limits.maxArgon2Parallelism) {
      fail("ERR_KDF", "Argon2id parameters exceed parser limits");
    }
  }
  if (!o.wrap || typeof o.wrap !== "object") fail("ERR_FORMAT", "wrap");
  const w = o.wrap as Record<string, unknown>;
  rejectUnknownKeys(w, ["alg", "iv", "ciphertext", "tag"]);
  if (w.alg !== "A256GCM") fail("ERR_NOT_IMPLEMENTED", "wrap alg");
  if (typeof w.iv !== "string" || typeof w.ciphertext !== "string" || typeof w.tag !== "string") fail("ERR_FORMAT", "wrap fields");
  base64urlToBytes(w.iv, 12);
  base64urlToBytes(w.ciphertext, 32);
  base64urlToBytes(w.tag, 16);
  return o as unknown as UnlockSlot;
}

export function validatePayloadShape(raw: unknown, limits: ParserLimits = DEFAULT_LIMITS): VaultPayload {
  if (!raw || typeof raw !== "object") fail("ERR_JSON", "payload is not an object");
  const o = raw as Record<string, unknown>;
  rejectUnknownKeys(o, [
    "identity",
    "msk",
    "keys",
    "preferred_keys",
    "metadata",
    "tombstones",
    "extensions",
    "critical_extensions",
  ]);
  if (!Array.isArray(o.keys) || o.keys.length > limits.maxKeyCount) fail("ERR_PARSER_LIMIT", "keys");
  for (const k of o.keys) validateKeyRecord(k, limits);
  if (!Array.isArray(o.tombstones) || o.tombstones.length > limits.maxTombstones) fail("ERR_PARSER_LIMIT", "tombstones");
  validateExtensions(o.extensions, false, limits);
  validateExtensions(o.critical_extensions, true, limits);
  assertCustodyBindings(o);
  return o as unknown as VaultPayload;
}

export function validateKeyRecord(raw: unknown, limits: ParserLimits = DEFAULT_LIMITS): KeyRecord {
  if (!raw || typeof raw !== "object") fail("ERR_FORMAT", "key record");
  const o = raw as Record<string, unknown>;
  rejectUnknownKeys(o, [
    "absolute_key_id",
    "short_key_id",
    "family",
    "algorithm",
    "algorithm_suite",
    "encoding",
    "purpose",
    "public_key",
    "private_key",
    "created_at",
    "status",
    "metadata",
  ]);
  if (typeof o.family !== "string" || isForbiddenFamily(o.family)) fail("ERR_FAMILY", String(o.family));
  if (!(KEY_FAMILIES as readonly string[]).includes(o.family)) fail("ERR_FAMILY", String(o.family));
  if (typeof o.encoding !== "string" || !(KEY_ENCODINGS as readonly string[]).includes(o.encoding)) {
    fail("ERR_ENCODING", String(o.encoding));
  }
  if (o.family === "openpgp" && o.encoding !== "openpgp-tsk") fail("ERR_ENCODING", "openpgp requires openpgp-tsk");
  if (o.family === "smime" && o.encoding === "openpgp-tsk") fail("ERR_ENCODING", "smime cannot use openpgp-tsk");
  if (o.algorithm_suite != null) {
    if (
      typeof o.algorithm_suite !== "string" ||
      !(ALGORITHM_SUITES as readonly string[]).includes(o.algorithm_suite)
    ) {
      fail("ERR_FORMAT", "algorithm_suite");
    }
  }
  if (!Array.isArray(o.purpose) || o.purpose.length < 1) fail("ERR_FORMAT", "purpose");
  const seen = new Set<string>();
  for (const p of o.purpose) {
    if (!(KEY_PURPOSES as readonly string[]).includes(p as string)) fail("ERR_FORMAT", "purpose");
    if (seen.has(p as string)) fail("ERR_FORMAT", "duplicate purpose");
    seen.add(p as string);
  }
  if (typeof o.status !== "string" || !(KEY_STATUSES as readonly string[]).includes(o.status)) fail("ERR_STATUS");
  if (typeof o.public_key !== "string") fail("ERR_ENCODING", "public_key");
  const pub = base64urlToBytes(o.public_key);
  if (pub.length > limits.maxKeyBytes) fail("ERR_PARSER_LIMIT", "public_key");
  if (o.private_key !== null) {
    if (typeof o.private_key !== "string") fail("ERR_ENCODING", "private_key");
    const priv = base64urlToBytes(o.private_key);
    if (priv.length > limits.maxKeyBytes) fail("ERR_PARSER_LIMIT", "private_key");
  }
  if (typeof o.short_key_id !== "string" || !/^[0-9A-F]{4}-[0-9A-F]{4}$/.test(o.short_key_id)) {
    fail("ERR_SHORT_KEY_ID");
  }
  if (o.metadata && (typeof o.metadata !== "object" || Object.keys(o.metadata as object).length > 0)) {
    fail("ERR_FORMAT", "unregistered key metadata; use extensions");
  }
  return o as unknown as KeyRecord;
}

function validateExtensions(raw: unknown, critical: boolean, limits: ParserLimits): Extension[] {
  if (!Array.isArray(raw)) fail("ERR_EXTENSION", "extensions must be an array");
  if (raw.length > limits.maxExtensions) fail("ERR_PARSER_LIMIT", "too many extensions");
  return raw.map((e) => {
    if (!e || typeof e !== "object") fail("ERR_EXTENSION");
    const o = e as Record<string, unknown>;
    rejectUnknownKeys(o, ["id", "critical", "data"]);
    if (typeof o.id !== "string" || !/^(std|exp|priv):[a-z0-9][a-z0-9._-]*$/.test(o.id)) fail("ERR_EXTENSION", "id");
    if (o.critical !== critical) fail("ERR_EXTENSION", "critical flag mismatch");
    if (!("data" in o)) fail("ERR_EXTENSION", "data required");
    const encoded = JSON.stringify(o.data);
    if (encoded.length > limits.maxExtensionBytes) fail("ERR_PARSER_LIMIT", "extension too large");
    if (o.id === KEY_CUSTODY_EXTENSION_ID) {
      validateKeyCustodyData(o.data, critical);
    } else if (critical) fail("ERR_CRITICAL_EXTENSION", `unknown critical extension ${o.id}`);
    return o as unknown as Extension;
  });
}

export function rejectUnknownKeys(obj: Record<string, unknown>, allowed: string[]): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) fail("ERR_FORMAT", `unknown field ${k}`);
  }
  for (const k of allowed) {
    if (!(k in obj) && k !== "kdf") {
      /* required checks happen elsewhere */
    }
  }
}

export function isRfc3339Z(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(s);
}

export function unknownCriticalExtensions(exts: Extension[]): Extension[] {
  return exts.filter((e) => e.critical);
}
