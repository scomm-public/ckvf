import { vaultAad, wrapAad } from "./aad.js";
import { bytesToBase64url, base64urlToBytes } from "./base64url.js";
import type { CkvfCrypto } from "./crypto-provider.js";
import { fail } from "./errors.js";
import { computeGenerationHash } from "./generation.js";
import { assertIdentity, makeIdentity } from "./identity.js";
import { jcs, utf8Decode, utf8Encode } from "./jcs.js";
import { keyIds } from "./keyid.js";
import { DEFAULT_LIMITS, TEST_ARGON2ID, type ParserLimits } from "./limits.js";
import { mergePayloads } from "./merge.js";
import { buildOpenPgpEd25519Public, buildOpenPgpEd25519Tsk, canonicalOpenPgpPublicKey } from "./openpgp.js";
import { buildPkcs8Ed25519, buildSpkiEd25519 } from "./pkcs8.js";
import {
  CKVF_CONTAINER_VERSION,
  CKVF_FORMAT,
  type IdentityType,
  type KeyEncoding,
  type KeyFamily,
  type KeyPurpose,
  type KeyRecord,
  type UnlockSlot,
  type UnlockedVault,
  type VaultContainer,
  type VaultPayload,
} from "./types.js";
import { parseJsonLimited, validateContainerShape, validatePayloadShape } from "./validate.js";
import { canReadVersion } from "./version.js";

export interface CreateVaultOptions {
  identityType: IdentityType;
  identityValue: string;
  password: string;
  crypto: CkvfCrypto;
  now?: string;
  kdf?: { m: number; t: number; p: number };
  limits?: ParserLimits;
}

export async function createVault(opts: CreateVaultOptions): Promise<UnlockedVault> {
  const crypto = opts.crypto;
  const now = rfc3339(opts.now);
  const identity = await makeIdentity(opts.identityType, opts.identityValue, crypto);
  const msk = await crypto.ed25519Generate();
  const msk_id = bytesToBase64url(await crypto.sha256(msk.publicKey));
  const payload: VaultPayload = {
    identity,
    msk: {
      current: {
        msk_id,
        algorithm: "Ed25519",
        public_key: bytesToBase64url(msk.publicKey),
        private_key: bytesToBase64url(msk.privateKey),
        activated_at: now,
      },
      history: [],
    },
    keys: [],
    preferred_keys: {},
    metadata: { created_at: now, updated_at: now },
    tombstones: [],
    extensions: [],
    critical_extensions: [],
  };
  const vek = crypto.randomBytes(32);
  const container = await sealPayload(crypto, payload, vek, {
    vault_id: bytesToBase64url(crypto.randomBytes(16)),
    generation: 1,
    previous_generation_hash: null,
    slots: [],
    password: opts.password,
    kdf: opts.kdf ?? TEST_ARGON2ID,
    now,
  });
  return { container, payload, vek };
}

export async function openVault(
  containerOrJson: VaultContainer | string,
  opts: { password: string; crypto: CkvfCrypto; slotId?: string; limits?: ParserLimits },
): Promise<UnlockedVault> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const container =
    typeof containerOrJson === "string"
      ? validateContainerShape(parseJsonLimited(containerOrJson, limits), limits)
      : validateContainerShape(containerOrJson, limits);
  if (!canReadVersion(container.version)) fail("ERR_VERSION");
  if (container.critical_extensions.length) fail("ERR_CRITICAL_EXTENSION");
  const expected = await computeGenerationHash(container, opts.crypto);
  if (expected !== container.generation_hash) fail("ERR_GENERATION_HASH");
  const slot = selectPasswordSlot(container, opts.slotId);
  const vek = await unwrapVek(opts.crypto, container.vault_id, slot, opts.password);
  let plaintext: Uint8Array;
  try {
    plaintext = await opts.crypto.aes256gcmDecrypt(
      vek,
      base64urlToBytes(container.crypto.iv, 12),
      base64urlToBytes(container.ciphertext),
      base64urlToBytes(container.tag, 16),
      vaultAad(container),
    );
  } catch {
    fail("ERR_AEAD_DECRYPT");
  }
  let json: unknown;
  try {
    json = JSON.parse(utf8Decode(plaintext));
  } catch {
    fail("ERR_JSON", "payload");
  }
  const payload = validatePayloadShape(json, limits);
  if (payload.critical_extensions.length) fail("ERR_CRITICAL_EXTENSION");
  await assertIdentity(payload.identity, opts.crypto);
  return { container, payload, vek };
}

export async function lockVault(unlocked: UnlockedVault, crypto: CkvfCrypto): Promise<VaultContainer> {
  return reseal(crypto, unlocked.payload, unlocked.vek, unlocked.container);
}

export function inspectPublicMetadata(containerOrJson: VaultContainer | string, limits: ParserLimits = DEFAULT_LIMITS) {
  const raw = typeof containerOrJson === "string" ? parseJsonLimited(containerOrJson, limits) : containerOrJson;
  if (!raw || typeof raw !== "object") fail("ERR_JSON");
  const o = raw as Record<string, unknown>;
  return {
    format: o.format,
    version: o.version,
    vault_id: o.vault_id,
    generation: o.generation,
    previous_generation_hash: o.previous_generation_hash,
    generation_hash: o.generation_hash,
    aead: (o.crypto as { aead?: string } | undefined)?.aead,
    unlock_methods: Array.isArray(o.unlock_slots)
      ? (o.unlock_slots as { slot_id: string; method: string }[]).map((s) => ({
          slot_id: s.slot_id,
          method: s.method,
        }))
      : [],
    extensions: Array.isArray(o.extensions) ? (o.extensions as { id: string }[]).map((e) => e.id) : [],
    critical_extensions: Array.isArray(o.critical_extensions)
      ? (o.critical_extensions as { id: string }[]).map((e) => e.id)
      : [],
  };
}

export async function importPrivateKey(
  unlocked: UnlockedVault,
  opts: {
    crypto: CkvfCrypto;
    family: KeyFamily;
    encoding: KeyEncoding;
    algorithm: string;
    algorithm_suite?: string | null;
    purpose: KeyPurpose[];
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    createdAt?: string;
    now?: string;
  },
): Promise<UnlockedVault> {
  const now = rfc3339(opts.now);
  let publicBytes = opts.publicKey;
  if (opts.encoding === "openpgp-tsk") {
    publicBytes = canonicalOpenPgpPublicKey(opts.publicKey, opts.privateKey);
  }
  const ids = await keyIds(publicBytes, opts.crypto);
  const record: KeyRecord = {
    absolute_key_id: ids.absolute_key_id,
    short_key_id: ids.short_key_id,
    family: opts.family,
    algorithm: opts.algorithm,
    algorithm_suite: opts.algorithm_suite ?? null,
    encoding: opts.encoding,
    purpose: opts.purpose,
    public_key: bytesToBase64url(publicBytes),
    private_key: bytesToBase64url(opts.privateKey),
    created_at: opts.createdAt ?? now,
    status: "active",
    metadata: {},
  };
  if (unlocked.payload.keys.some((k) => k.absolute_key_id === record.absolute_key_id)) {
    fail("ERR_KEY_ID", "key already present");
  }
  const payload: VaultPayload = {
    ...unlocked.payload,
    keys: [...unlocked.payload.keys, record],
    metadata: { ...unlocked.payload.metadata, updated_at: now },
  };
  const container = await incrementAndSeal(opts.crypto, payload, unlocked.vek, unlocked.container);
  return { container, payload, vek: unlocked.vek };
}

export function getKey(unlocked: UnlockedVault, absoluteKeyId: string): KeyRecord | undefined {
  return unlocked.payload.keys.find((k) => k.absolute_key_id === absoluteKeyId);
}

export function findKeysByShortId(unlocked: UnlockedVault, shortId: string): KeyRecord[] {
  return unlocked.payload.keys.filter((k) => k.short_key_id === shortId.toUpperCase());
}

export function exportPrivateKey(unlocked: UnlockedVault, absoluteKeyId: string): Uint8Array {
  const key = getKey(unlocked, absoluteKeyId);
  if (!key) fail("ERR_KEY_ID", "not found");
  if (key.private_key === null) fail("ERR_KEY_ID", "private key deleted");
  return base64urlToBytes(key.private_key);
}

export async function retireKey(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  absoluteKeyId: string,
  now?: string,
): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  if (!unlocked.payload.keys.some((k) => k.absolute_key_id === absoluteKeyId)) fail("ERR_KEY_ID");
  const payload: VaultPayload = {
    ...unlocked.payload,
    keys: unlocked.payload.keys.map((k) =>
      k.absolute_key_id === absoluteKeyId ? { ...k, status: "retired" as const } : k,
    ),
    metadata: { ...unlocked.payload.metadata, updated_at: ts },
  };
  const container = await incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return { container, payload, vek: unlocked.vek };
}

export async function changePassword(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  oldPassword: string,
  newPassword: string,
  now?: string,
  kdf?: { m: number; t: number; p: number },
): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  const oldSlot = selectPasswordSlot(unlocked.container);
  await unwrapVek(crypto, unlocked.container.vault_id, oldSlot, oldPassword);
  const replacement = await wrapPasswordSlot(
    crypto,
    unlocked.container.vault_id,
    unlocked.vek,
    newPassword,
    ts,
    kdf ?? slotKdf(oldSlot),
    oldSlot.slot_id,
  );
  const slots = unlocked.container.unlock_slots.map((s) => (s.slot_id === oldSlot.slot_id ? replacement : s));
  const container = await commitEnvelopeChange(crypto, unlocked, slots);
  return { container, payload: unlocked.payload, vek: unlocked.vek };
}

export async function addUnlockSlot(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  password: string,
  now?: string,
  kdf?: { m: number; t: number; p: number },
): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  const slot = await wrapPasswordSlot(crypto, unlocked.container.vault_id, unlocked.vek, password, ts, kdf);
  const container = await commitEnvelopeChange(crypto, unlocked, [...unlocked.container.unlock_slots, slot]);
  return { container, payload: unlocked.payload, vek: unlocked.vek };
}

export async function removeUnlockSlot(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  slotId: string,
): Promise<UnlockedVault> {
  if (unlocked.container.unlock_slots.length <= 1) fail("ERR_SLOT_ID", "cannot remove last slot");
  const slots = unlocked.container.unlock_slots.filter((s) => s.slot_id !== slotId);
  if (slots.length === unlocked.container.unlock_slots.length) fail("ERR_SLOT_ID", "unknown slot");
  const container = await commitEnvelopeChange(crypto, unlocked, slots);
  return { container, payload: unlocked.payload, vek: unlocked.vek };
}

export async function mergeVaults(
  a: UnlockedVault,
  b: UnlockedVault,
  crypto: CkvfCrypto,
  now?: string,
): Promise<UnlockedVault> {
  if (a.container.vault_id !== b.container.vault_id) fail("ERR_FORMAT", "vault_id");
  const ts = rfc3339(now);
  const merged = mergePayloads(a.payload, b.payload, a.container.unlock_slots, b.container.unlock_slots);
  merged.payload.metadata.updated_at = ts;
  const parentGen = Math.max(a.container.generation, b.container.generation);
  const container = await sealPayload(crypto, merged.payload, a.vek, {
    vault_id: a.container.vault_id,
    generation: parentGen + 1,
    previous_generation_hash: a.container.generation_hash,
    slots: merged.slots,
  });
  return { container, payload: merged.payload, vek: a.vek };
}

export async function replaceMsk(unlocked: UnlockedVault, crypto: CkvfCrypto, now?: string): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  const next = await crypto.ed25519Generate();
  const msk_id = bytesToBase64url(await crypto.sha256(next.publicKey));
  const old = unlocked.payload.msk.current;
  const payload: VaultPayload = {
    ...unlocked.payload,
    msk: {
      current: {
        msk_id,
        algorithm: "Ed25519",
        public_key: bytesToBase64url(next.publicKey),
        private_key: bytesToBase64url(next.privateKey),
        activated_at: ts,
      },
      history: [
        ...unlocked.payload.msk.history,
        {
          msk_id: old.msk_id,
          algorithm: old.algorithm,
          public_key: old.public_key,
          activated_at: old.activated_at,
          retired_at: ts,
        },
      ],
    },
    metadata: { ...unlocked.payload.metadata, updated_at: ts },
  };
  const container = await incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return { container, payload, vek: unlocked.vek };
}

export function serializeContainer(container: VaultContainer): string {
  return jcs(container);
}

export async function addTestOpenPgpKey(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  now?: string,
): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  const pair = await crypto.ed25519Generate();
  const created = Math.floor(Date.parse(ts) / 1000);
  return importPrivateKey(unlocked, {
    crypto,
    family: "openpgp",
    encoding: "openpgp-tsk",
    algorithm: "Ed25519",
    purpose: ["sign", "encrypt"],
    privateKey: buildOpenPgpEd25519Tsk(pair.privateKey, pair.publicKey, created),
    publicKey: buildOpenPgpEd25519Public(pair.publicKey, created),
    now: ts,
  });
}

export async function addTestPkcs8Key(
  unlocked: UnlockedVault,
  crypto: CkvfCrypto,
  now?: string,
): Promise<UnlockedVault> {
  const ts = rfc3339(now);
  const pair = await crypto.ed25519Generate();
  return importPrivateKey(unlocked, {
    crypto,
    family: "smime",
    encoding: "pkcs8",
    algorithm: "Ed25519",
    purpose: ["sign", "encrypt"],
    privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
    publicKey: buildSpkiEd25519(pair.publicKey),
    now: ts,
  });
}

function rfc3339(now?: string): string {
  if (now) return now;
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function sealPayload(
  crypto: CkvfCrypto,
  payload: VaultPayload,
  vek: Uint8Array,
  opts: {
    vault_id: string;
    generation: number;
    previous_generation_hash: string | null;
    slots: UnlockSlot[];
    password?: string;
    kdf?: { m: number; t: number; p: number };
    now?: string;
    iv?: Uint8Array;
  },
): Promise<VaultContainer> {
  let slots = opts.slots;
  if (opts.password) {
    const slot = await wrapPasswordSlot(crypto, opts.vault_id, vek, opts.password, rfc3339(opts.now), opts.kdf);
    slots = [slot, ...slots];
  }
  const iv = opts.iv ?? crypto.randomBytes(12);
  const draft: VaultContainer = {
    format: CKVF_FORMAT,
    version: CKVF_CONTAINER_VERSION,
    vault_id: opts.vault_id,
    generation: opts.generation,
    previous_generation_hash: opts.previous_generation_hash,
    generation_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    crypto: { aead: "A256GCM", iv: bytesToBase64url(iv) },
    unlock_slots: slots,
    ciphertext: "",
    tag: "AAAAAAAAAAAAAAAAAAAAAA",
    extensions: [],
    critical_extensions: [],
  };
  const enc = await crypto.aes256gcmEncrypt(vek, iv, utf8Encode(jcs(payload)), vaultAad(draft));
  draft.ciphertext = bytesToBase64url(enc.ciphertext);
  draft.tag = bytesToBase64url(enc.tag);
  draft.generation_hash = await computeGenerationHash(draft, crypto);
  return draft;
}

async function incrementAndSeal(
  crypto: CkvfCrypto,
  payload: VaultPayload,
  vek: Uint8Array,
  previous: VaultContainer,
): Promise<VaultContainer> {
  return sealPayload(crypto, payload, vek, {
    vault_id: previous.vault_id,
    generation: previous.generation + 1,
    previous_generation_hash: previous.generation_hash,
    slots: previous.unlock_slots,
  });
}

async function reseal(
  crypto: CkvfCrypto,
  payload: VaultPayload,
  vek: Uint8Array,
  previous: VaultContainer,
): Promise<VaultContainer> {
  return sealPayload(crypto, payload, vek, {
    vault_id: previous.vault_id,
    generation: previous.generation,
    previous_generation_hash: previous.previous_generation_hash,
    slots: previous.unlock_slots,
    iv: base64urlToBytes(previous.crypto.iv, 12),
  });
}

async function commitEnvelopeChange(
  crypto: CkvfCrypto,
  unlocked: UnlockedVault,
  slots: UnlockSlot[],
): Promise<VaultContainer> {
  return sealPayload(crypto, unlocked.payload, unlocked.vek, {
    vault_id: unlocked.container.vault_id,
    generation: unlocked.container.generation + 1,
    previous_generation_hash: unlocked.container.generation_hash,
    slots,
  });
}

async function wrapPasswordSlot(
  crypto: CkvfCrypto,
  vaultId: string,
  vek: Uint8Array,
  password: string,
  now: string,
  kdf?: { m: number; t: number; p: number },
  slotId?: string,
): Promise<UnlockSlot> {
  const params = { m: TEST_ARGON2ID.m, t: TEST_ARGON2ID.t, p: TEST_ARGON2ID.p, ...kdf };
  const salt = crypto.randomBytes(16);
  const slot_id = slotId ?? bytesToBase64url(crypto.randomBytes(16));
  const kek = await crypto.argon2id({
    password: utf8Encode(password),
    salt,
    m: params.m,
    t: params.t,
    p: params.p,
    keyLength: 32,
  });
  const iv = crypto.randomBytes(12);
  const wrapped = await crypto.aes256gcmEncrypt(kek, iv, vek, wrapAad("password-argon2id", slot_id, vaultId));
  return {
    slot_id,
    method: "password-argon2id",
    created_at: now,
    kdf: {
      alg: "Argon2id",
      salt: bytesToBase64url(salt),
      m: params.m,
      t: params.t,
      p: params.p,
      key_length: 32,
    },
    wrap: {
      alg: "A256GCM",
      iv: bytesToBase64url(iv),
      ciphertext: bytesToBase64url(wrapped.ciphertext),
      tag: bytesToBase64url(wrapped.tag),
    },
  };
}

async function unwrapVek(crypto: CkvfCrypto, vaultId: string, slot: UnlockSlot, password: string): Promise<Uint8Array> {
  if (slot.method !== "password-argon2id" || !slot.kdf) fail("ERR_UNLOCK", "password slot required");
  const kek = await crypto.argon2id({
    password: utf8Encode(password),
    salt: base64urlToBytes(slot.kdf.salt),
    m: slot.kdf.m,
    t: slot.kdf.t,
    p: slot.kdf.p,
    keyLength: slot.kdf.key_length,
  });
  try {
    return await crypto.aes256gcmDecrypt(
      kek,
      base64urlToBytes(slot.wrap.iv, 12),
      base64urlToBytes(slot.wrap.ciphertext, 32),
      base64urlToBytes(slot.wrap.tag, 16),
      wrapAad(slot.method, slot.slot_id, vaultId),
    );
  } catch {
    fail("ERR_WRAP_DECRYPT");
  }
}

function selectPasswordSlot(container: VaultContainer, slotId?: string): UnlockSlot {
  const slots = container.unlock_slots.filter((s) => s.method === "password-argon2id");
  if (!slots.length) fail("ERR_UNLOCK", "no password slot");
  if (slotId) {
    const found = slots.find((x) => x.slot_id === slotId);
    if (!found) fail("ERR_SLOT_ID");
    return found;
  }
  return slots[0]!;
}

function slotKdf(slot: UnlockSlot): { m: number; t: number; p: number } {
  if (!slot.kdf) return { m: TEST_ARGON2ID.m, t: TEST_ARGON2ID.t, p: TEST_ARGON2ID.p };
  return { m: slot.kdf.m, t: slot.kdf.t, p: slot.kdf.p };
}
