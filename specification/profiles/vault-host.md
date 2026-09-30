# Vault host

**Status:** Optional operator profile. **Not operated by SComm.**

An operator MAY store CKVF ciphertext and MAY evaluate pepper OPRF. SComm
clients follow [scomm-local-vault.md](scomm-local-vault.md) and
[untrusted-sync.md](untrusted-sync.md) instead, and do not call the origins
below. This profile is not a Discovery Document and it is not part of
[`discovery-protocol`](https://github.com/scomm-public/discovery-protocol).

| Mode | Origin |
| --- | --- |
| Debug | `http://127.0.0.1:3001` |
| Production | `https://vault.scomm.ai` |

The directory and its mailer are a different origin (`http://127.0.0.1:3000`,
`https://discovery.scomm.ai`). The vault host does not send mail and does not
accept a mailbox address. At open and rebind the client sends
`mailbox_sha256` (the unsalted mailbox hash). The host stores that locator
and fetches the armed MSK public key from `GET /v1/msk?sha256=` on the
directory. It does not store the public key. Later signature checks use a
fresh fetch of that same locator.

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
  "mailbox_sha256": "<64 hex>",
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

The proof signature uses `msk.algorithm` (`ed25519` or `mldsa65-ed25519`) over
this UTF-8 text, each line ending in LF. `mldsa65-ed25519` is the concatenation
defined in Discovery Protocol `spec/authorization.md`: both halves MUST verify.

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
3. fetch `GET /v1/msk?sha256={mailbox_sha256}` and require that armed key
   and algorithm to equal `msk`;
4. verify the proof signature with that key, check the timestamp window,
   and spend the nonce;
5. spend the grant `jti`;
6. bind `identity_id → vault_id → mailbox_sha256` only if the identity has
   no vault (`409 vault_already_open` otherwise). The public key is not
   stored.

A proof or grant failure is `401`. The grant is not spent when the proof
fails, so a stolen grant without the MSK private key is useless and a
client bug does not burn the user's grant.

`first_device` is optional and registers the calling device (§5).

### 2.3 MSK rebind

`POST /v1/vault/{vault_id}/msk` has the same body without `vault_id`,
including `mailbox_sha256`. The grant purpose is `replace_msk`,
`msk_fingerprint` names the **new** MSK, and the proof `operation` is
`arm_replacement_msk`, signed by the new MSK. The host returns
`404 unknown_principal` if `vault_id` is not bound to `identity_id`. It
checks the new key against Discovery and does not store it. Replaced
public keys come from Discovery's archived list, so older generations stay
verifiable.

### 2.4 Records

`POST /v1/vault/{vault_id}/records` stores one generation:

```json
{
  "identity_id": "<64 hex>",
  "container": { "format": "CKVF", "version": "1.0", "vault_id": "...", ... },
  "msk_signature": { "algorithm": "ed25519", "value": "<base64url 64>" },
  "license_device_id": "<optional; host licensing>"
}
```

The signature is by the identity's armed MSK (`msk_signature.algorithm` matches
the armed algorithm) over this UTF-8 text,
each line ending in LF:

```text
SComm/Pubkey/1/vault_records_put
principal=<identity_id>
vault_id=<vault_id>
generation=<container.generation>
generation_hash=<container.generation_hash>
```

The host checks, without decrypting (SPEC.md §11.2):

1. `format` is `CKVF` and `version` is `1.0` or `1.1` (`400 unsupported_version`
   otherwise);
2. `container.vault_id` equals the path `vault_id`, which is bound to
   `identity_id`; an unbound pair is `404 unknown_principal`;
3. `generation` is a positive integer and `previous_generation_hash` is
   `null` exactly when `generation` is `1`;
4. `generation_hash` equals base64url(SHA-256(JCS(container without
   `generation_hash`)));
5. the signature verifies with the armed MSK (`401 invalid_signature`).

Any other container error is `400 vault_corrupt`, and a container larger than
the host limit is `413`. The host does not parse the encrypted payload.

The generation MUST be exactly head + 1 with `previous_generation_hash` equal
to the head's `generation_hash`. Resending the stored generation with the same
hash returns `200` with `"duplicate": true`. Anything else is
`409 generation_conflict`:

```json
{
  "error": {
    "code": "generation_conflict",
    "message": "...",
    "details": {
      "generation": 2,
      "stored_generation_hash": "<base64url, when that generation exists>",
      "head_generation": 2,
      "head_generation_hash": "<base64url>"
    }
  }
}
```

On a conflict the client fetches the head, merges (SPEC.md §12), and uploads
head + 1.

`GET /v1/vault/{vault_id}/current` and `.../generation/{n}` return:

```json
{
  "record": {
    "container": { },
    "generation": 3,
    "generation_hash": "<base64url>",
    "msk_signature": { "algorithm": "ed25519", "value": "<base64url>" },
    "created_at": "<RFC 3339>"
  },
  "msk_public_key": "<base64url 32>",
  "archived_msk_public_keys": ["<base64url 32>"]
}
```

Clients verify `msk_signature` against `msk_public_key` or an archived key
before trusting `container`.

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
grant. This host fetches the armed MSK from Discovery `GET /v1/msk?sha256=` on every verification and does not store the public key. `identity_id` is that same lowercase hex SHA-256 of the canonical mailbox. There is no identity OPRF.

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

## 5. Pairing (addendum)

The host does not keep a device-read-key registry. A device that holds the MSK signs reads with the `Msk` scheme. Pairing and recovery reads use a single-use token or an OTP grant because that device does not have the MSK yet.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/pairing/{session_id}` | New device creates a session. Body includes `b_retrieval_hash` = SHA-256 of a secret only that device keeps. Requires an open vault. |
| GET | `/v1/pairing/{session_id}` | Pending status. Does not return the new device id. |
| PUT | `/v1/pairing/{session_id}/response` | Approving device responds. `msk_signature` is verified against the Discovery MSK before the session becomes RESPONDED. |
| POST | `/v1/pairing/{session_id}/retrieve` | Body `retrieval_secret`. Constant-time match against `b_retrieval_hash` returns the sealed envelope and a single-use read token. |

Unknown, expired, completed, wrong-secret, and identity-mismatch sessions all answer `404 not_found`.

Rules:

- Every mutation carries an MSK proof whose nonce the host spends once per `(identity_id, operation, nonce)`.
- The host never sees the VEK, a KEK, or the MSK private key. Pairing transfers them under a CPace session key.
- Removing a device means the remaining device rotates the VEK and replaces the MSK. Dropping a slot alone does not revoke a device that already unwrapped the VEK.

## 6. Reference client

Container libraries in this repository (`packages/*`) MUST NOT call these
routes; they create, open, and merge containers without I/O. The reference
HTTP client for this profile is `scomm_vault_client` (Dart), which depends
on the `ckvf` Dart package and implements §2–§5 plus the pepper OPRF.
