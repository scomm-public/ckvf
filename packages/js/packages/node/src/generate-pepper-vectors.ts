/**
 * Writes test-vectors/pepper-oprf/poprf.json: RFC 9497 POPRF (mode 0x02,
 * ristretto255-SHA512) transcripts for profiles/pepper-oprf.md. Blind and
 * proof randomness are derived from fixed labels so the file is reproducible.
 * The Dart tool packages/dart/tool/pepper_vectors.dart builds the matching
 * containers from the `rwd` values.
 */
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { ristretto255_oprf } from "@noble/curves/ed25519.js";

const KEY_INFO = "CKVF-pepper-key-v1";
const INFO_PREFIX = "CKVF-pepper-v1";

const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const seq = (start: number) => Uint8Array.from({ length: 16 }, (_, i) => (start + i) & 0xff);

function detRng(label: string) {
  let counter = 0;
  return (n = 32) => {
    const out = new Uint8Array(n);
    for (let off = 0; off < n; off += 64) {
      const block = createHash("sha512").update(`${label}/${counter++}`).digest();
      out.set(block.subarray(0, Math.min(64, n - off)), off);
    }
    return out;
  };
}

function info(vaultId: string, slotId: string) {
  return new Uint8Array(
    Buffer.concat([
      Buffer.from(INFO_PREFIX, "ascii"),
      Buffer.from([0]),
      Buffer.from(vaultId, "ascii"),
      Buffer.from([0]),
      Buffer.from(slotId, "ascii"),
    ]),
  );
}

function findTestVectors(start: string): string {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "test-vectors");
    if (existsSync(path.join(candidate, "VERSION"))) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("test-vectors/ not found from " + start);
}

async function main() {
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const kid = "vector-pepper-1";
  const keys = ristretto255_oprf.poprf(new Uint8Array(0)).deriveKeyPair(seed, new TextEncoder().encode(KEY_INFO));
  const vaultId = b64u(seq(0x01));

  const inputs = [
    {
      id: "password-oprf-unlock",
      method: "password-oprf-argon2id",
      slot_id: b64u(seq(0xa0)),
      secret: "CKVF-TEST-PEPPER-PASSWORD",
    },
    {
      id: "recovery-code-oprf-unlock",
      method: "recovery-code-oprf-argon2id",
      slot_id: b64u(seq(0xb0)),
      secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    },
  ];

  const cases = inputs.map((c) => {
    const poprf = ristretto255_oprf.poprf(info(vaultId, c.slot_id));
    const input = new TextEncoder().encode(c.secret);
    const { blind, blinded, tweakedKey } = poprf.blind(input, keys.publicKey, detRng(`${c.id}/blind`));
    const { evaluated, proof } = poprf.blindEvaluate(keys.secretKey, blinded, detRng(`${c.id}/proof`));
    const rwd = poprf.finalize(input, blind, evaluated, blinded, proof, tweakedKey);
    if (hex(rwd) !== hex(poprf.evaluate(keys.secretKey, input))) throw new Error("finalize != evaluate");
    return {
      ...c,
      info: b64u(info(vaultId, c.slot_id)),
      blind: b64u(blind),
      blinded: b64u(blinded),
      tweaked_key: b64u(tweakedKey),
      evaluated: b64u(evaluated),
      proof: b64u(proof),
      rwd: b64u(rwd),
    };
  });

  const out = {
    banner: "TEST KEY — NEVER USE IN PRODUCTION",
    profile: "profiles/pepper-oprf.md",
    suite: "ristretto255-SHA512",
    mode: "poprf",
    key_info: KEY_INFO,
    info_format: `${INFO_PREFIX} || 0x00 || vault_id || 0x00 || slot_id (ASCII)`,
    key: { kid, seed: b64u(seed), secret_key: b64u(keys.secretKey), public_key: b64u(keys.publicKey) },
    vault_id: vaultId,
    cases,
  };

  const dir = path.join(findTestVectors(path.dirname(fileURLToPath(import.meta.url))), "pepper-oprf");
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "poprf.json"), `${JSON.stringify(out, null, 2)}\n`, "utf8");
  console.log(`wrote ${cases.length} POPRF cases to ${dir}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
