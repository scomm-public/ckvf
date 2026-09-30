# Cryptographic Key Vault Format (CKVF)

**SComm.AI Draft 0.1** — the SComm.AI-maintained portable vault format, published at [`scomm-public/ckvf`](https://github.com/scomm-public/ckvf). This is **not** an IETF standard, Internet-Draft, RFC, or IETF consensus document.

CKVF is a lightweight, portable, user-controlled format for an independently encrypted vault of current and historical private keys bound to a verified Identity, authorized by a Master Signing Key (MSK), and synchronizable across devices without giving a hosting service plaintext keys.

SComm.AI maintains this specification and the reference SDKs. SComm does not host vault ciphertext. A container with an offline unlock slot opens without Discovery and without a vault host. This repository is the container format, the profiles, and the reference SDKs. It does **not** implement Discovery Protocol HTTP or directory MSK enroll. Those live in [`discovery-protocol`](https://github.com/scomm-public/discovery-protocol) on `discovery.scomm.ai`.

**Normative specification:** [specification/SPEC.md](specification/SPEC.md)

## Layout

| Path | Role | License |
| --- | --- | --- |
| [`specification/`](specification/) | SComm.AI Draft 0.1 (normative) | BSD-2-Clause |
| [`schemas/`](schemas/) | JSON Schemas | BSD-2-Clause |
| [`registries/`](registries/) | CKVF registries | BSD-2-Clause |
| [`test-vectors/`](test-vectors/) | Pinned interoperability fixtures (`VERSION`, not `main`) | BSD-2-Clause |
| [`conformance/`](conformance/) | Conformance profiles and result schema | Apache-2.0 |
| [`packages/js`](packages/js) | JavaScript / TypeScript (`@ckvf/core`, `@ckvf/node`, `@ckvf/browser`, `@ckvf/conformance`) | Apache-2.0 |
| [`packages/dart`](packages/dart) | Dart (`ckvf`) | Apache-2.0 |
| [`packages/rust`](packages/rust) | Rust (`ckvf` / `scomm_vault`) | Apache-2.0 |
| [`packages/go`](packages/go), [`dotnet`](packages/dotnet), [`kotlin`](packages/kotlin), [`swift`](packages/swift) | SDK templates | Apache-2.0 |

Content keys (OpenPGP TSK vs S/MIME PKCS#8/PKCS#12, `algorithm_suite`): [docs/content-keys.md](docs/content-keys.md).

Layering vs Discovery Protocol: [docs/layering.md](docs/layering.md).

## Packages

| Package | Language | Status |
| --- | --- | --- |
| [`packages/js`](packages/js) | JavaScript / TypeScript | Implemented (0.1.0) |
| [`packages/dart`](packages/dart) | Dart | Implemented (0.1.0) |
| [`packages/go`](packages/go) | Go | Template |
| [`packages/rust`](packages/rust) | Rust | Implemented (0.1.0) |
| [`packages/dotnet`](packages/dotnet) | .NET | Template |
| [`packages/kotlin`](packages/kotlin) | Kotlin | Template |
| [`packages/swift`](packages/swift) | Swift | Template |

## Contract

Every package:

- Consumes the same **specification**, **schemas**, **registries**, and **test-vectors**.
- **MUST NOT** silently redefine CKVF behavior to match language conventions.
- Pins **test-vector `VERSION`**, **not** `main`.
- Exposes capability queries (`canReadVersion` / `canWriteVersion`, supported algorithms, key encodings, unlock methods).
- **MUST NEVER** silently rewrite a vault to a newer container version on open. Upgrade is an explicit write.

Language implementations of the same container version MUST interoperate: JS → `vault.ckvf` → Dart (and later Rust, etc.).

## What does *not* belong here

| Concern | Belongs in |
| --- | --- |
| Discovery Document HTTP (`GET /v1/mailboxes/...`), directory MSK enroll, mailer OTP | [`discovery-protocol`](https://github.com/scomm-public/discovery-protocol) on `discovery.scomm.ai` |
| Vault host HTTP and pepper OPRF | Optional operator profile only: [specification/profiles/vault-host.md](specification/profiles/vault-host.md). SComm does not operate it. Container libraries in `packages/` do not call it. |
| Merging Discovery HTTP into this repo | **Forbidden** |

SComm product clients depend on these packages for portable vault files.

## Develop

```bash
# Dart
cd packages/dart && dart pub get && dart analyze && dart test

# JavaScript
cd packages/js && npm ci && npm run build && npm test
```

Dart conformance loads `test-vectors/` from the repository root (or `CKVF_TEST_VECTORS`) and pins `packages/dart/test-vectors/VERSION`.

See each package's README for install and API details.

## License

| Material | License |
| --- | --- |
| Specification, schemas, registries, test vectors | [BSD-2-Clause](LICENSE-SPEC) |
| SDKs and conformance tooling | [Apache-2.0](LICENSE) |

Do not copy text from IETF RFCs into this repository; cite the original RFC documents.
