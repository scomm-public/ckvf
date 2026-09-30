# CKVF threat model

SComm.AI Draft 0.1. This document is informative except where it restates MUST/SHOULD requirements already in [SPEC.md](SPEC.md).

CKVF is a **portable encrypted vault format** plus signed lifecycle operations. It is not a complete identity-provider, mail user agent, or KMS product. Threats are split into:

- **CKVF mitigations** — required or recommended by the format/protocol.
- **Application / environment responsibilities** — OS, UI, email, DNS, implementation quality, operational policy.

Attacker capabilities considered: local file access, network attacker on sync, malicious sync operator, compromised device, compromised SDK, identity-channel attacker, and resource-exhaustion via malformed files.

## Summary table

| Threat | CKVF mitigation | Application / environment |
| --- | --- | --- |
| Stolen vault file | AEAD + random VEK; password not stored; Argon2id wrapping | Strong password or hardware-backed slot; disk encryption |
| Offline password guessing | Argon2id recommended params; reject weak KDF params | Password policy; rate-limit **online** attempts; consider device slot |
| Malicious sync service | Opaque ciphertext; generation hashes; no plaintext required | Authenticate transport; verify hashes client-side |
| Rollback | `generation` + `previous_generation_hash` + `generation_hash` | Persist last-seen head; alert on downgrade |
| Replay of operations | Nonce + timestamp; reject nonce reuse | Maintain replay cache; optional clock-skew **policy** |
| Stale device | Merge: no silent LWW; stale MUST NOT delete newer keys | Prompt user on conflict; retire lost devices |
| Lost device | Multiple slots; `REMOVE_DEVICE` | Inventory devices; password recovery path |
| Compromised MSK | Ownership proof to replace; no historical MSK private keys | Detect anomaly; notify Identity; revoke published keys |
| Compromised encryption key (VEK) | Rotate the VEK on device revocation (local-vault profile); GCM prevents undetected modification without VEK | Minimize unlocked time; process isolation; treat VEK leak as full vault compromise of that generation |
| Short Key ID collision | Absolute Key ID authoritative; tolerate collisions | UI must not key only on short IDs |
| Malicious imported key | Parser limits; canonical SPKI/packet hashing | Family-native validation before trust/publish |
| Malformed vault | Fail closed; reject extra core JSON; GCM verify | Do not “repair” ciphertext |
| Resource exhaustion | Default parser limits (16 MiB, 1024 keys, Argon2 caps, …) | Additional process limits |
| Identity takeover | Proofs bound to operation; MSK replace requires proof | Protect email/DNS; out-of-band notify |
| Email takeover | email-otp: random, expire, single-use, bound, rate-limit | Mailbox security, 2FA on mail, recovery channels |
| DNS takeover | dns-01: authoritative lookup, expiry, hash binding | DNSSEC where possible; registrar lock |
| Supply-chain (SDK) | Spec is small and explicit; no vendor API in core | Pin versions; reproducible builds; review |
| Browser XSS | Out of format scope | Lock vault; isolate privileged origin |
| Server compromise | Server has no VEK if protocol followed | Minimize logs; do not persist unlocked state |

## 1. Stolen vault

**Scenario.** Attacker copies `vault.ckvf` from disk or backup.

**Impact.** Offline attack on unlock slots. If a password slot is used, guessing is possible. Ciphertext does not yield keys without VEK.

**CKVF.** AES-256-GCM; VEK random; wrap AAD binds `method`, `slot_id`, `vault_id`; passwords never stored.

**Not CKVF.** Full-disk encryption, screen lock, backup encryption at rest, phishing of the password.

## 2. Offline password guessing

**Scenario.** Attacker has the file and brute-forces the password against Argon2id + wrap tag.

**CKVF.** Memory-hard KDF; minimum `m`/`t`; recommended RFC 9106 second option; MUST NOT silently reduce parameters.

**Not CKVF.** User education; passphrase managers; hardware unlock as additional slot.

## 3. Malicious sync service

**Scenario.** `pubkey.scomm.ai` or any other store substitutes blobs, lies about generation, or tries to obtain keys.

**CKVF.** Service MUST NOT need plaintext private keys. Clients verify `generation_hash` and AEAD. Directory publishes only current public keys. SPEC forbids bending the core to one vendor.

**Not CKVF.** TLS, operator access control, legal compulsion of the operator (who still lacks VEK).

## 4. Rollback

**Scenario.** Service or attacker presents an old generation.

**CKVF.** Parent hash chain; stale generation MUST be detected; no silent last-writer-wins.

**Not CKVF.** Client persistence of last-seen `(vault_id, generation, generation_hash)`; user-visible rollback warnings.

## 5. Replay

**Scenario.** Attacker replays `DELETE_PRIVATE_KEY` or `REMOVE_DEVICE`.

**CKVF.** Unique 256-bit nonce; timestamp; reject reuse in the consumer’s window. ±5 minutes is optional server skew, **not** a format constant.

**Not CKVF.** Clock synchronization; durable nonce stores; distinguishing “file moved between own devices” vs network replay.

## 6. Stale device

**Scenario.** Phone offline for a month pushes an old view that retired or deleted keys.

**CKVF.** Union keys by `absolute_key_id`; status severity monotonic; private key kept if either side has it unless authorized delete is current; preferred keys conflict; MSK mismatch hard-fails; slot removal conservative.

**Not CKVF.** UX to resolve `ERR_MERGE_*`; marking a device as retired in the application.

## 7. Lost device

**Scenario.** Device with a device-wrap slot is lost.

**CKVF.** Other slots still unwrap the same VEK; `REMOVE_DEVICE` can drop the lost slot on next commit; vendor keystore APIs are not normative (lost-device behavior of TEE is out of scope).

**Not CKVF.** Remote wipe of the platform keystore; user still having a password slot.

## 8. Compromised MSK

**Scenario.** Ed25519 seed leaks.

**Impact.** Attacker can sign operations. Without VEK they cannot decrypt the vault. With a service that accepts signatures they may publish keys or, if they also unlock a client, mutate the vault.

**CKVF.** `REPLACE_MSK` needs Identity ownership proof; old MSK private key dropped from current payload; history keeps public keys.

**Not CKVF.** Detection (unexpected `REPLACE_MSK` email); publication of MSK revocation in the directory.

## 9. Compromised encryption key (VEK)

**Scenario.** VEK dumped from memory after unlock.

**Impact.** All payload secrets for that VEK are readable. Unlock slots do not compartmentalize keys from each other.

**CKVF.** Device revocation in the SComm local-vault profile samples a new VEK, re-encrypts the single payload, and re-wraps remaining slots. A copy of an older generation remains decryptable with the old VEK's slots. GCM prevents undetected modification without the VEK.

**Not CKVF.** Minimize unlocked time; process isolation. Revocation does not erase a VEK the device already extracted.

## 10. Short Key ID collision

**Scenario.** Two keys share `ABCD-EF12`. A UI confirms the wrong key.

**CKVF.** Short IDs are hints; operations use `absolute_key_id`; applications MUST tolerate collisions.

**Not CKVF.** Display disambiguation; never use short IDs in URLs as the only parameter.

## 11. Malicious imported key

**Scenario.** A huge or hostile PKCS #12 / TSK is added.

**CKVF.** Size and nesting limits; canonical public-key extraction rules; `ADD_KEY` still requires MSK.

**Not CKVF.** OpenPGP signature validity, X.509 path validation, malware scanning of certificate bags.

## 12. Malformed vault

**Scenario.** Truncated JSON, padded base64, extra core fields, wrong AAD.

**CKVF.** Reject unknown core properties; unpadded base64url only; recompute hashes and IDs; GCM fail closed (`ERR_AEAD_DECRYPT`).

**Not CKVF.** “Best effort” repair tools that re-encrypt under a new VEK without user intent.

## 13. Resource exhaustion

**Scenario.** `m` and `p` enormous; 10,000 nested objects; 2 GiB ciphertext.

**CKVF.** Default limits in SPEC Appendix C.

**Not CKVF.** OS cgroups; API request timeouts.

## 14. Identity takeover (generic)

**Scenario.** Attacker proves they control the Identity and calls `REPLACE_MSK`.

**CKVF.** Proofs expire, are single-use, and are bound to operation and MSK public key. Vault Identity mismatch rejects merge.

**Not CKVF.** The strength of email and DNS as identifiers; secondary verification.

## 15. Email takeover

**Scenario.** Attacker reads the OTP mailbox.

**CKVF profile.** Random OTP, expiry, single-use, bound to operation, rate-limited, never stored in the vault, no vendor OTP API in the spec.

**Not CKVF.** Mail-provider 2FA, forwarding rules, SIM swap on recovery phone.

## 16. DNS takeover

**Scenario.** Attacker writes `_ckvf-challenge` TXT at the registrar or via a compromised nameserver.

**CKVF profile.** Challenge is SHA-256 of a JCS object including nonce, expiry, operation, and MSK public key; lookup MUST use authoritative DNS; replay protection; **not** claimed to be ACME.

**Not CKVF.** DNSSEC, registrar locks, multi-person DNS changes.

## 17. Supply-chain

**Scenario.** A dependency swaps AES-GCM for a no-op or weakens Argon2.

**CKVF.** Algorithms are fixed for `"1.0"`; test vectors (when published) allow cross-checks; no vendor secure-storage API in the core.

**Not CKVF.** Packaging, code signing, language ecosystem audits.

## 18. Browser XSS

**Scenario.** Script on a privileged origin calls into an unlocked vault.

**CKVF.** No browser-specific normative API.

**Not CKVF.** CSP, origin isolation, lock-on-hide, never putting the VEK in `localStorage` in plaintext.

## 19. Server compromise

**Scenario.** Directory/sync host is fully owned.

**CKVF.** Operator still should not have VEK; treat container as opaque; do not log payloads.

**Not CKVF.** HSM for *server* TLS keys; intrusion response; the attacker may still replace public directory entries — clients SHOULD pin or compare MSK updates against ownership proofs.

## 20. Residual risk

CKVF does not make stolen passwords safe, does not make email a high-assurance authenticator, and does not survive VEK extraction from a running client. Those are explicit non-goals. The format’s job is a precise, mergeable, independently encrypted vault that a hostile host cannot read.

## 21. Additional adversaries (SComm local vault)

These restate the format rules for the SComm deployment. They do not add primitives.

| Adversary | What they obtain | What they do not obtain |
| --- | --- | --- |
| Stolen CKVF file | Ciphertext, slot methods, Argon2 parameters, generation numbers | VEK, unless they also have an unlock secret or the device KEK |
| Malicious storage provider | Object names, ciphertext, sizes, timing | Plaintext keys, VEK, recovery secret |
| Compromised sync account | Ability to substitute or roll back objects, subject to client checks | A client that remembers the head refuses `ERR_ROLLBACK` and still needs an unlock secret |
| Stale or rolled-back storage | An older valid container | Acceptance as the current head |
| Revoked device | Any secret it decrypted before revocation | The ability to publish a new head that restores its slot or lowers lifecycle severity |
| Stolen device | Device KEK, if the platform keystore is unlocked or extracted | Other devices' KEKs; a VEK rotated after revocation |
| Compromised mailbox | Ability to receive OTP and replace the directory MSK | The VEK. OTP is not a KDF input |
| Compromised Discovery control (MSK) | Authority to sign directory changes and vault mutations **after** the attacker can also unlock a copy | The VEK, from the MSK alone |
| Compromised Discovery service | Public keys, armed MSK public key, grant issuance | Vault ciphertext and the VEK. Discovery does not store them |
| Lost recovery passphrase and all device slots | Nothing further from SComm | The payload. SComm has no escrow key |
| Modified CKVF object | A file the client rejects when `generation_hash` or AEAD fails | A silent plaintext change |
| Concurrent offline devices | Forked generations | A silent last-writer-wins merge. SPEC.md §12 still applies |

Compromise of Discovery alone MUST NOT enable decryption of a vault.

