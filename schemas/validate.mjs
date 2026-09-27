#!/usr/bin/env node
/**
 * Compile CKVF JSON Schemas (draft 2020-12) with Ajv and check structural fixtures.
 * Schemas do not replace specification/SPEC.md.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const dir = path.dirname(fileURLToPath(import.meta.url));

const SCHEMA_FILES = [
  "extension.schema.json",
  "identity.schema.json",
  "unlock-slot.schema.json",
  "key-record.schema.json",
  "vault-container.schema.json",
  "vault-payload.schema.json",
  "signed-operation.schema.json",
];

const B64_12 = "AAECAwQFBgcICQoL"; // 16 chars, 12 bytes
const B64_16 = "ASNFZ4mrze8BI0VniavN7w"; // 22 chars, 16 bytes (SPEC example vault_id)
const B64_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
const B64_64 = `${B64_32}${B64_32}`.slice(0, 86);
const TS = "2026-08-17T00:00:00Z";

const keyRecord = {
  absolute_key_id: B64_32,
  short_key_id: "648A-A5C5",
  family: "openpgp",
  algorithm: "Ed25519",
  algorithm_suite: null,
  encoding: "openpgp-tsk",
  purpose: ["sign"],
  public_key: B64_32,
  private_key: B64_32,
  created_at: TS,
  status: "active",
  metadata: {},
};

const passwordSlot = {
  slot_id: B64_16,
  method: "password-argon2id",
  created_at: TS,
  kdf: {
    alg: "Argon2id",
    salt: B64_16,
    m: 65536,
    t: 3,
    p: 4,
    key_length: 32,
  },
  wrap: {
    alg: "A256GCM",
    iv: B64_12,
    ciphertext: B64_32,
    tag: B64_16,
  },
};

const oprfSlot = {
  ...passwordSlot,
  method: "password-oprf-argon2id",
  oprf: {
    suite: "ristretto255-SHA512",
    mode: "poprf",
    kid: "pw-2026-09",
    public_key: B64_32,
  },
};

const fixtures = [
  {
    schema: "extension.schema.json",
    valid: { id: "std:example", critical: false, data: {} },
    invalid: { id: "std:example", critical: false, data: {}, extra: true },
  },
  {
    schema: "identity.schema.json",
    valid: {
      type: "email",
      value: "user@example.com",
      identity_id: B64_32,
    },
    invalid: {
      type: "email",
      value: "user@example.com",
      identity_id: B64_32,
      extra: true,
    },
  },
  {
    schema: "unlock-slot.schema.json",
    valid: passwordSlot,
    invalid: { ...passwordSlot, extra: true },
  },
  {
    schema: "key-record.schema.json",
    valid: keyRecord,
    invalid: { ...keyRecord, family: "pqc" },
  },
  {
    schema: "vault-container.schema.json",
    valid: {
      format: "CKVF",
      version: "1.0",
      vault_id: B64_16,
      generation: 1,
      previous_generation_hash: null,
      generation_hash: B64_32,
      crypto: { aead: "A256GCM", iv: B64_12 },
      unlock_slots: [],
      ciphertext: "AQ",
      tag: B64_16,
      extensions: [],
      critical_extensions: [],
    },
    invalid: {
      format: "CKVF",
      version: "1.0",
      vault_id: B64_16,
      generation: 1,
      previous_generation_hash: null,
      generation_hash: B64_32,
      crypto: { aead: "A256GCM", iv: B64_12 },
      unlock_slots: [],
      ciphertext: "AQ",
      tag: B64_16,
      extensions: [],
      critical_extensions: [],
      extra: true,
    },
  },
  {
    schema: "vault-payload.schema.json",
    valid: {
      identity: {
        type: "email",
        value: "user@example.com",
        identity_id: B64_32,
      },
      msk: {
        current: {
          msk_id: B64_32,
          algorithm: "Ed25519",
          public_key: B64_32,
          private_key: B64_32,
          activated_at: TS,
        },
        history: [],
      },
      keys: [],
      preferred_keys: {},
      metadata: { created_at: TS, updated_at: TS },
      tombstones: [],
      extensions: [],
      critical_extensions: [],
    },
    invalid: {
      identity: {
        type: "email",
        value: "user@example.com",
        identity_id: B64_32,
      },
      msk: {
        current: {
          msk_id: B64_32,
          algorithm: "Ed25519",
          public_key: B64_32,
          private_key: B64_32,
          activated_at: TS,
        },
        history: [],
      },
      keys: [],
      preferred_keys: {},
      metadata: { created_at: TS, updated_at: TS, note: "no" },
      tombstones: [],
      extensions: [],
      critical_extensions: [],
    },
  },
  {
    schema: "signed-operation.schema.json",
    valid: {
      body: {
        protocol: "CKVF",
        protocol_version: "1.0",
        operation: "UPDATE_METADATA",
        identity_id: B64_32,
        vault_id: B64_16,
        generation: 1,
        nonce: B64_32,
        timestamp: TS,
        payload_hash: B64_32,
      },
      payload: { updated_at: TS },
      signature: {
        algorithm: "Ed25519",
        msk_id: B64_32,
        value: B64_64,
      },
    },
    invalid: {
      body: {
        protocol: "CKVF",
        protocol_version: "1.0",
        operation: "UPDATE_METADATA",
        identity_id: B64_32,
        vault_id: B64_16,
        generation: 1,
        nonce: B64_32,
        timestamp: TS,
        payload_hash: B64_32,
      },
      payload: { updated_at: TS, extra: true },
      signature: {
        algorithm: "Ed25519",
        msk_id: B64_32,
        value: B64_64,
      },
    },
  },
];

const extraCases = [
  {
    name: "device-wrap slot omits kdf",
    schema: "unlock-slot.schema.json",
    instance: {
      slot_id: B64_16,
      method: "device-wrap-a256gcm",
      created_at: TS,
      wrap: passwordSlot.wrap,
    },
    ok: true,
  },
  {
    name: "device-wrap slot rejects kdf",
    schema: "unlock-slot.schema.json",
    instance: {
      slot_id: B64_16,
      method: "device-wrap-a256gcm",
      created_at: TS,
      kdf: passwordSlot.kdf,
      wrap: passwordSlot.wrap,
    },
    ok: false,
  },
  {
    name: "password-oprf slot accepted",
    schema: "unlock-slot.schema.json",
    instance: oprfSlot,
    ok: true,
  },
  {
    name: "recovery-code-oprf slot accepted",
    schema: "unlock-slot.schema.json",
    instance: { ...oprfSlot, method: "recovery-code-oprf-argon2id" },
    ok: true,
  },
  {
    name: "oprf slot requires oprf object",
    schema: "unlock-slot.schema.json",
    instance: { ...passwordSlot, method: "password-oprf-argon2id" },
    ok: false,
  },
  {
    name: "oprf slot rejects m below 65536",
    schema: "unlock-slot.schema.json",
    instance: { ...oprfSlot, kdf: { ...oprfSlot.kdf, m: 32768 } },
    ok: false,
  },
  {
    name: "oprf slot rejects t below 3",
    schema: "unlock-slot.schema.json",
    instance: { ...oprfSlot, kdf: { ...oprfSlot.kdf, t: 2 } },
    ok: false,
  },
  {
    name: "password-argon2id rejects oprf object",
    schema: "unlock-slot.schema.json",
    instance: { ...passwordSlot, oprf: oprfSlot.oprf },
    ok: false,
  },
  {
    name: "smime + openpgp-tsk rejected",
    schema: "key-record.schema.json",
    instance: { ...keyRecord, family: "smime", encoding: "openpgp-tsk" },
    ok: false,
  },
  {
    name: "generation 2 requires previous_generation_hash",
    schema: "vault-container.schema.json",
    instance: {
      format: "CKVF",
      version: "1.0",
      vault_id: B64_16,
      generation: 2,
      previous_generation_hash: null,
      generation_hash: B64_32,
      crypto: { aead: "A256GCM", iv: B64_12 },
      unlock_slots: [],
      ciphertext: "AQ",
      tag: B64_16,
      extensions: [],
      critical_extensions: [],
    },
    ok: false,
  },
  {
    name: "padded base64url rejected",
    schema: "identity.schema.json",
    instance: {
      type: "dns",
      value: "example.com",
      identity_id: `${B64_32}=`,
    },
    ok: false,
  },
  {
    name: "short_key_id must be uppercase",
    schema: "key-record.schema.json",
    instance: { ...keyRecord, short_key_id: "648a-a5c5" },
    ok: false,
  },
  {
    name: "ADD_KEY payload accepts key record",
    schema: "signed-operation.schema.json",
    instance: {
      body: {
        protocol: "CKVF",
        protocol_version: "1.0",
        operation: "ADD_KEY",
        identity_id: B64_32,
        vault_id: B64_16,
        generation: 1,
        nonce: B64_32,
        timestamp: TS,
        payload_hash: B64_32,
      },
      payload: { key: keyRecord },
      signature: { algorithm: "Ed25519", msk_id: B64_32, value: B64_64 },
    },
    ok: true,
  },
];

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: false,
});

for (const file of SCHEMA_FILES) {
  const schema = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
  ajv.addSchema(schema);
}

for (const file of SCHEMA_FILES) {
  const validate = ajv.getSchema(file);
  if (!validate) {
    fail(`failed to compile ${file}`);
    continue;
  }
  console.log(`compiled ${file}`);
}

for (const fixture of fixtures) {
  const validate = ajv.getSchema(fixture.schema);
  if (validate(fixture.valid) !== true) {
    fail(`${fixture.schema}: expected valid fixture, got ${ajv.errorsText(validate.errors)}`);
  }
  if (validate(fixture.invalid) !== false) {
    fail(`${fixture.schema}: expected invalid fixture to be rejected`);
  }
}

for (const test of extraCases) {
  const validate = ajv.getSchema(test.schema);
  const result = validate(test.instance) === true;
  if (result !== test.ok) {
    fail(
      `${test.name}: expected ${test.ok ? "accept" : "reject"}, got ${result ? "accept" : "reject"}${
        result ? "" : ` (${ajv.errorsText(validate.errors)})`
      }`,
    );
  }
}

if (process.exitCode) {
  console.error("schema validation failed");
  process.exit(1);
}

console.log("all schema fixtures passed");
