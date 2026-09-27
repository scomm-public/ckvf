# CKVF test vectors

Versioned interoperability fixtures for Cryptographic Key Vault Format (CKVF) SComm.AI Draft 0.1.

**TEST KEY — NEVER USE IN PRODUCTION.** All private keys, MSKs, and passwords in this directory are fixtures.

CKVF is the SComm.AI-maintained portable vault format and is **not** an IETF standard. Vectors MUST be usable offline (no Discovery HTTP required).

## Pinning

Consumers **MUST** pin this directory by the contents of [VERSION](VERSION) (currently `0.1.0`) or a matching git tag of the `ckvf` repository.

Do **not** pin `main`.

## Layout

| Path | Contents |
| --- | --- |
| `VERSION` | Vector-set SemVer |
| `manifest.json` | Vector ids, expect pass/fail, optional error code |
| `vectors/<id>.json` | Fixture for that id |
| `keys/` | Extra test-key notes |
| `pepper-oprf/` | [pepper-oprf](../specification/profiles/pepper-oprf.md) and device-wrap slots: `poprf.json` transcripts, own `manifest.json` and `vectors/` |

`pepper-oprf/` is a separate set so readers without these unlock methods can still run the core manifest. Regenerate with `npm run build && node packages/node/dist/generate-pepper-vectors.js` in `packages/js`, then `dart run tool/pepper_vectors.dart` in `packages/dart`. Pepper fixtures use the profile floor `m=65536`, `t=3`, `p=1`.

Password used by encrypted fixtures: `CKVF-TEST-PASSWORD`.

KDF parameters in v0.1.0 fixtures are the SPEC §6.5 minima (`m=16384` KiB, `t=2`, `p=1`) so CI can run them. Production writers SHOULD use the RFC 9106 second recommended option (`m=65536`, `t=3`, `p=4`).

## Short Key IDs

**Short Key IDs are lookup hints and are not unique identifiers.** See `vectors/short-key-id-collision.json`. Applications MUST tolerate collisions. `absolute_key_id` is authoritative.

## License

[BSD-2-Clause](LICENSE).
