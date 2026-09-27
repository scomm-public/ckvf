# Profile: email-otp

**Status:** SComm.AI Draft 0.1 profile  
**Normative for implementations that claim this profile**  
**Not an IETF standard**  
**Not a vendor API**

This profile defines **security properties** for proving control of an `email` Identity when establishing or replacing a CKVF MSK, or when a service requires Identity ownership for another registered operation. It does **not** specify a particular mail vendor, SMS gateway, TOTP app, or HTTP API.

Core data model, cryptography, and operations remain in [SPEC.md](SPEC.md).

## 1. Applicability

- Identity `type` MUST be `"email"`.
- Canonicalization and `identity_id` MUST follow SPEC.md Section 7.2–7.1.
- This profile is the default verification method identifier `"email-otp"` in `ESTABLISH_MSK` / `REPLACE_MSK` payloads (`verification_method`).

## 2. Goals

Prove that the presenter can currently read mail at the canonical email address, with a proof that is:

- random;
- time-limited;
- single-use;
- bound to the CKVF operation and to the MSK public key being established or installed;
- rate-limited;
- **never stored in the vault**.

## 3. Proof object (verifier-side, not in the vault)

A verifier (the user agent in an offline ceremony, or a directory service in the [reference-key-service profile](reference-key-service.md)) holds an ephemeral record:

| Field | Requirement |
| --- | --- |
| `identity_id` | Bound Identity |
| `operation` | Exact operation name (`ESTABLISH_MSK`, `REPLACE_MSK`, or another registered operation this profile is used for) |
| `msk_public_key` | 32-byte Ed25519 public key of the MSK being established or installed |
| `nonce` | 256-bit CSPRNG value |
| `otp` | High-entropy secret delivered to the mailbox (see §5) |
| `issued_at` / `expires_at` | RFC 3339 UTC |
| `consumed` | Boolean |

This record MUST NOT be written into the CKVF container, encrypted payload, key `metadata`, or extensions.

`proof_id` in a signed payload (SPEC Appendix B.9) is an opaque handle the verifier maps to this record. The handle MUST NOT equal the OTP.

## 4. Binding

The OTP (or a derived verifier) MUST authenticate the tuple:

```
(protocol="CKVF", protocol_version="1.0", verification_method="email-otp",
 identity_type="email", identity_value=<canonical>,
 operation, msk_public_key, nonce)
```

Implementations MAY implement binding by hashing that tuple (UTF-8 JCS of a JSON object with those keys) into the mail body next to the OTP, or by using the OTP only as a key that MACs the tuple. The mail body is not a CKVF file; the **property** is that an OTP stolen from a *different* operation or MSK MUST NOT succeed.

## 5. OTP generation

- The OTP MUST be generated with a CSPRNG.
- Entropy MUST be at least 128 bits if the value is an opaque token, or at least 20 bits of uniform digits only if additional online rate limiting and short expiry make online guessing impractical — **opaque tokens ≥ 128 bits are RECOMMENDED**.
- The OTP MUST expire. A default expiry of 10 minutes is RECOMMENDED. Verifiers MUST reject expired proofs.
- The OTP MUST be single-use: successful consumption sets `consumed` and MUST prevent reuse (`ERR_REPLAY` / `ERR_OWNERSHIP`).
- The OTP MUST NOT be the MSK seed, VEK, or password.

### 5.1 SComm hosted profile: 64-bit codes

The SComm.AI directory sends a 64-bit CSPRNG value encoded as 11 Base62
characters (`0-9A-Za-z`, no separators). That is below the 128-bit
recommendation above and above the 20-bit floor. The shorter code exists so
people can read and type it from a mail message. It is acceptable because
online guessing is the only attack, and it is bounded:

- a code expires after 10 minutes and allows at most 5 verify attempts, with
  the counter updated atomically;
- issuance is rate-limited per mailbox and per client address;
- the code is stored only as a salted hash and spent atomically on success;
- the resulting grant is bound to the MSK fingerprint (§4), so a code
  observed for one operation cannot arm a different key.

With 5 attempts per code, a guess succeeds with probability about 5 / 2^64
per issued code. A deployment that relaxes any of these bounds MUST return
to 128-bit opaque tokens.

Mailbox OTP is not an authenticator TOTP. Applications MUST NOT ask for a
6-digit code for this profile.

## 6. Delivery

How the OTP reaches the mailbox (SMTP, a mail API, a local MUA displaying a locally generated code) is **out of scope**. This profile MUST NOT be implemented as “call vendor X’s OTP API”.

The message SHOULD include the canonical Identity, the operation name, and a warning that it is a CKVF ownership proof.

## 7. Rate limiting

Verifiers MUST rate-limit:

- issuance per Identity;
- issuance per presenter identifier they have (IP, account);
- validation attempts per proof.

Exact numeric limits are operational, not file-format constants. Unbounded issuance or checking is NOT RECOMMENDED.

## 8. REPLACE_MSK and ESTABLISH_MSK

- `ESTABLISH_MSK` MUST present a valid, unconsumed, unexpired email-otp proof bound to that operation and new MSK public key, and MUST fail if an MSK already exists.
- `REPLACE_MSK` MUST present a **fresh** proof unless a future recovery profile registered as an extension says otherwise (SPEC.md Section 8.4).
- Historical MSK private keys MUST NOT be stored.

## 9. What this profile does not do

- It does not make email a phishing-resistant authenticator.
- It does not define DKIM, S/MIME encryption of the OTP message, or a particular mail template.
- It does not store mail headers in the vault.
- It does not require SComm or `pubkey.scomm.ai`.

## 10. Threat notes

See [THREAT-MODEL.md](../THREAT-MODEL.md) (email takeover). Mailbox compromise defeats this profile. Applications SHOULD notify the address of MSK replacement and SHOULD offer dns-01 as an alternative when the Identity is a domain.
