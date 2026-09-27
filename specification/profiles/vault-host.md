# Vault host

CKVF ciphertext is stored by the vault host. This profile is the hosted
record API. It is not a Discovery Document and it is not part of
[`discovery-protocol`](https://github.com/scomm-public/discovery-protocol).

| Mode | Origin |
| --- | --- |
| Debug | `http://127.0.0.1:3001` |
| Production | `https://vault.scomm.ai` |

The directory and its mailer are a different origin (`http://127.0.0.1:3000`,
`https://discovery.scomm.ai`). The vault host does not send mail and does not
accept a mailbox address or `mailboxSha256`. It never calls the directory at
runtime; the directory's view of the mailbox reaches it only inside a signed
grant.

## 1. Identifiers

- `identity_id`: 64 lowercase hex, the OPRF identity (§2.1). Wire name is
  always `identity_id`.
- `vault_id`: minted by the client when it creates the container: 16 random
  bytes, base64url without padding (22 characters), as in SPEC.md §4.1.
  Hosts MAY accept the older 64-hex form until existing clients have
  re-opened with a new id.

## 2. Routes

| Method | Path | Authorization |
| --- | --- | --- |
| GET | `/v1/id/oprf/key` | none |
| POST | `/v1/id/oprf/evaluate` | none; rate-limited |
| POST | `/v1/vault/open` | `vault_open` grant + MSK proof |
| POST | `/v1/vault/{vault_id}/msk` | `replace_msk` grant + proof by the new MSK |
| POST | `/v1/vault/{vault_id}/records` | MSK signature over the generation |
| GET | `/v1/vault/{vault_id}/current` | read authorization (§4) |
| GET | `/v1/vault/{vault_id}/generation/{n}` | read authorization (§4) |
| GET | `/v1/vault/{vault_id}/pending-mutations` | read authorization (§4) |
| GET | `/v1/pw-oprf/keys` | none |
| POST | `/v1/pw-oprf/evaluate` | read authorization (§4); rate-limited per `vault_id` |

### 2.1 Identity OPRF

`POST /v1/id/oprf/evaluate` with `{ "blind" }` returns
`{ "evaluation", "proof" }`. RFC 9497 `ristretto255-SHA512`; the evaluation
is the mode `0x00` output and `proof` is the VOPRF DLEQ proof against the
key from `GET /v1/id/oprf/key` (`{ "suite", "public_key" }`). Finalize is the
same in both modes, so `identity_id` does not depend on whether the client
verifies. Clients SHOULD verify the proof against a pinned public key.
`identity_id` is the first 32 octets of Finalize over the canonical mailbox,
in hex. The info string
`Scomm/Pubkey/identity/v1` is a label only and is not mixed into Finalize.
The OPRF secret stays on this host.

### 2.2 Open

`POST /v1/vault/open`:

```json
{
  "identity_id": "<64 hex>",
  "vault_id": "<vault id>",
  "otp_grant": "<grant>",
  "msk": { "algorithm": "ed25519", "public_key": "<base64url 32>" },
  "msk_proof": {
    "protocol_version": 1,
    "operation": "vault_open",
    "principal": "<identity_id>",
    "timestamp": <unix ms>,
    "nonce": "<base64url ≥ 16 random bytes>",
    "payload": { "vault_id": "<vault id>", "grant_jti": "<grant jti>" },
    "signature": { "algorithm": "ed25519", "value": "<base64url 64>" }
  },
  "first_device": { }
}
```

The proof signature is Ed25519 over this UTF-8 text, each line ending in LF:

```text
SComm/Pubkey/1/vault_open
principal=<identity_id>
timestamp=<unix ms>
nonce=<nonce>
payload_sha256=<hex SHA-256 of the RFC 8785 JCS of payload>
```

The timestamp window is five minutes.

The host MUST, in this order:

1. verify the grant (§3) without spending it, and require `purpose=vault_open`,
   the same `identity_id`, and `msk_fingerprint` equal to the SHA-256 of
   `msk.public_key`;
2. require `msk_proof.payload` to name this `vault_id` and the grant's `jti`;
3. verify the proof signature with `msk.public_key`, check the timestamp
   window, and spend the nonce;
4. spend the grant `jti`;
5. bind `identity_id → vault_id → MSK` only if the identity has no vault
   (`409 vault_already_open` otherwise).

A proof or grant failure is `401`. The grant is not spent when the proof
fails, so a stolen grant without the MSK private key is useless and a
client bug does not burn the user's grant.

`first_device` is optional and registers the calling device (§5).

### 2.3 MSK rebind

`POST /v1/vault/{vault_id}/msk` has the same body without `vault_id`. The
grant purpose is `replace_msk`, `msk_fingerprint` names the **new** MSK, and
the proof `operation` is `arm_replacement_msk`, signed by the new MSK. The
host returns `404 unknown_principal` if `vault_id` is not bound to
`identity_id`. It archives the previous MSK public key so older generations
stay verifiable.

### 2.4 Records

`POST /v1/vault/{vault_id}/records` stores one generation. The body is the
CKVF outer container JSON plus an MSK signature. The host checks `format`,
`version`, `vault_id`, `generation`, `previous_generation_hash`, and
`generation_hash` without decrypting (SPEC.md §11.2), and rejects a
generation that does not extend its current head. It does not parse the
encrypted payload.

### 2.5 Pepper OPRF

`POST /v1/pw-oprf/evaluate` serves the `password-oprf-argon2id` and
`recovery-code-oprf-argon2id` unlock methods. Request, response, key
handling, and rate limits are in [pepper-oprf.md](pepper-oprf.md).

## 3. Grant

The discovery mailer signs the grant; the full format, key set, and test
vectors are in the Discovery Protocol
([otp-grants.md](https://github.com/scomm-public/discovery-protocol/blob/main/spec/otp-grants.md)).
It is repeated here so the two do not drift:

```text
Scomm/grant/v1
iss=https://discovery.scomm.ai
aud=<space-separated audience origins>
kid=<signing key id>
purpose=<purpose>
identity_id=<64 lowercase hex>
msk_fingerprint=<64 lowercase hex SHA-256 of the raw MSK public key>
amr=<otp | id_token>
idp=<google | microsoft | empty>
exp=<unix ms>
jti=<base64url of 16 random bytes>
```

Each line ends in LF. Token = `base64url(text) "." base64url(Ed25519(text))`.

The host MUST check the signature against its configured key set by `kid`,
`iss`, that its own origin is in `aud`, `exp`, and the purpose, and MUST
spend `jti` atomically (shared store in production, fail closed when the
store is unavailable). Production hosts MUST refuse any key committed to a
public repository.

Purposes consumed here: `vault_open`, `replace_msk`, `recovery_envelope`,
`recovery_generation`, `vault_backup`.

A vault is opened only after the directory already has an armed MSK for that
mailbox. The mailer enforces that precondition by refusing vault-purpose
grants without one and by writing the armed key's fingerprint into the
grant. This host never looks up the directory.

## 4. Read authorization

A read route accepts exactly one of:

| Header | Meaning |
| --- | --- |
| `Authorization: Device <…>` | Signature by a registered device key over method, path, timestamp, and a nonce that the host spends |
| `Authorization: PairingRead <token>` | Short-lived token issued during device pairing (§5); single use |
| `Authorization: OtpGrant <grant>` | A vault-audience grant for `recovery_generation` or `vault_backup`; single use |

A grant-authorized `GET current` MAY return an `oprf_token` that authorizes
up to five `POST /v1/pw-oprf/evaluate` calls for that `vault_id` within ten
minutes, so a new device can unlock a password or recovery slot after one
mailbox proof.

Reads are also rate-limited per `identity_id`.

## 5. Devices and pairing (addendum)

These routes are hosted today and are proposed for the next draft of this
profile:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/vault/{vault_id}/devices` | Device inventory (read authorization) |
| POST | `/v1/vault/{vault_id}/devices` | Register a device key (MSK-signed) |
| DELETE | `/v1/vault/{vault_id}/devices/{device_id}` | Remove a device (MSK-signed) |
| POST | `/v1/vault/{vault_id}/pairing` | Start CPace pairing; relays opaque messages between devices |

Rules:

- Every mutation carries an MSK proof whose nonce the host spends once per
  `(identity_id, operation, nonce)`.
- The host never sees the VEK, a KEK, or the MSK private key. Pairing
  transfers them end to end between devices under a CPace session key.
- High-risk mutations (removing the last device, MSK rebind) SHOULD be
  delayed or confirmed on another device where the application supports it.

## 6. Reference client

Container libraries in this repository (`packages/*`) MUST NOT call these
routes; they create, open, and merge containers without I/O. The reference
HTTP client for this profile is `scomm_vault_client` (Dart), which depends
on the `ckvf` Dart package and implements §2–§5 plus the pepper OPRF.
