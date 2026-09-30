import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  aadObject,
  canonicalizeDns,
  canonicalizeEmail,
  identityId,
  jcs,
  mergePayloads,
  shortKeyIdFromDigest,
  utf8Encode,
  type KeyPurpose,
} from "./index.js";

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

const shaCrypto = {
  async sha256(data: Uint8Array) {
    return sha256(data);
  },
} as { sha256: (data: Uint8Array) => Promise<Uint8Array> };

test("RFC 8785 JCS sorts keys", () => {
  assert.equal(jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(jcs({ format: "CKVF", version: "1.0" }), '{"format":"CKVF","version":"1.0"}');
});

test("SPEC example AAD JCS", () => {
  const aad = aadObject({
    format: "CKVF",
    version: "1.0",
    vault_id: "ASNFZ4mrze8BI0VniavN7w",
    generation: 1,
    previous_generation_hash: null,
    crypto: { aead: "A256GCM", iv: "AAECAwQFBgcICQoL" },
    unlock_slots: [],
    extensions: [],
    critical_extensions: [],
  });
  assert.equal(
    jcs(aad),
    '{"critical_extensions":[],"crypto":{"aead":"A256GCM","iv":"AAECAwQFBgcICQoL"},"extensions":[],"format":"CKVF","generation":1,"previous_generation_hash":null,"unlock_slots":[],"vault_id":"ASNFZ4mrze8BI0VniavN7w","version":"1.0"}',
  );
});

test("email and dns canonicalization", () => {
  assert.equal(canonicalizeEmail("User@Example.COM"), "user@example.com");
  assert.equal(canonicalizeEmail("  alice@EXAMPLE.com  "), "alice@example.com");
  assert.equal(canonicalizeDns("Example.COM."), "example.com");
  assert.equal(canonicalizeDns("example.com..."), "example.com");
});

test("identity_id examples from SPEC", async () => {
  const emailId = await identityId("email", "user@example.com", shaCrypto as never);
  const dnsId = await identityId("dns", "example.com", shaCrypto as never);
  assert.equal(emailId, "tmwIJmeStJDSo9giG47rc8MKlVNxXPBKhG1GIcReptA");
  assert.equal(dnsId, "LpMoG_ozO2qxNonqsDwgJUBJEvma97aY8Z9q1njrZ-M");
});

test("short key id from digest prefix", () => {
  const digest = Uint8Array.from([0x64, 0x8a, 0xa5, 0xc5, 0, 0, 0, 0]);
  assert.equal(shortKeyIdFromDigest(digest), "648A-A5C5");
});

test("merge unions keys and escalates status", () => {
  const key = (id: string, status: "active" | "retired") =>
    ({
      absolute_key_id: id,
      short_key_id: "0000-0000",
      family: "openpgp",
      algorithm: "Ed25519",
      algorithm_suite: null,
      encoding: "openpgp-tsk",
      purpose: ["sign"] as KeyPurpose[],
      public_key: "AA",
      private_key: "BB",
      created_at: "2026-08-17T00:00:00Z",
      status,
      metadata: {} as Record<string, never>,
    }) as const;
  const payload = (keys: ReturnType<typeof key>[]) => ({
    identity: { type: "email" as const, value: "a@example.com", identity_id: "x" },
    msk: {
      current: {
        msk_id: "m",
        algorithm: "Ed25519" as const,
        public_key: "p",
        private_key: "s",
        activated_at: "2026-08-17T00:00:00Z",
      },
      history: [],
    },
    keys: [...keys],
    preferred_keys: {},
    metadata: { created_at: "2026-08-17T00:00:00Z", updated_at: "2026-08-17T00:00:00Z" },
    tombstones: [],
    extensions: [],
    critical_extensions: [],
  });
  const merged = mergePayloads(payload([key("K1", "active"), key("K2", "active"), key("K3", "active")]), payload([
    key("K1", "retired"),
    key("K2", "active"),
    key("K4", "active"),
  ]), [], []);
  assert.deepEqual(
    merged.payload.keys.map((k) => k.absolute_key_id).sort(),
    ["K1", "K2", "K3", "K4"],
  );
  assert.equal(merged.payload.keys.find((k) => k.absolute_key_id === "K1")?.status, "retired");
});

test("device-bound custody is not filled from another generation", () => {
  const key = (status: "active" | "revoked", private_key: string | null) =>
    ({
      absolute_key_id: "K1",
      short_key_id: "0000-0000",
      family: "openpgp",
      algorithm: "Ed25519",
      algorithm_suite: null,
      encoding: "openpgp-tsk",
      purpose: ["sign"] as KeyPurpose[],
      public_key: "AA",
      private_key,
      created_at: "2026-08-17T00:00:00Z",
      status,
      metadata: {} as Record<string, never>,
    }) as const;
  const base = {
    identity: { type: "email" as const, value: "a@example.com", identity_id: "x" },
    msk: {
      current: {
        msk_id: "m",
        algorithm: "Ed25519" as const,
        public_key: "p",
        private_key: "s",
        activated_at: "2026-08-17T00:00:00Z",
      },
      history: [],
    },
    preferred_keys: {},
    metadata: { created_at: "2026-08-17T00:00:00Z", updated_at: "2026-08-17T00:00:00Z" },
    tombstones: [],
    extensions: [],
  };
  const merged = mergePayloads(
    { ...base, keys: [key("active", "BB")], critical_extensions: [] },
    {
      ...base,
      keys: [key("revoked", null)],
      critical_extensions: [
        {
          id: "std:key-custody",
          critical: true,
          data: { absolute_key_id: "K1", custody: "device-bound", key_ref: "keystore:1" },
        },
      ],
    },
    [],
    [],
  );
  assert.equal(merged.payload.keys[0]?.status, "revoked");
  assert.equal(merged.payload.keys[0]?.private_key, null);
  assert.equal(merged.payload.critical_extensions[0]?.id, "std:key-custody");
});

test("utf8 helper roundtrip", () => {
  assert.equal(Buffer.from(utf8Encode("CKVF")).toString(), "CKVF");
});

test("algorithm_suite is rsa|ecc|pqc inside openpgp/smime families", async () => {
  const { ALGORITHM_SUITES, algorithmSuiteFromAlgorithm } = await import("./registries.js");
  assert.deepEqual([...ALGORITHM_SUITES], ["rsa", "ecc", "pqc"]);
  assert.equal(algorithmSuiteFromAlgorithm("Ed25519"), "ecc");
  assert.equal(algorithmSuiteFromAlgorithm("ML-DSA-65+Ed25519"), "pqc");
  assert.equal(algorithmSuiteFromAlgorithm("rsa4096"), "rsa");
});
