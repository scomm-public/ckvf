# 0003. SComm unlock is offline

## Status

Accepted

## Context

`password-argon2id` and `device-wrap-a256gcm` unwrap the VEK with no network. Pepper methods (`password-oprf-argon2id`, `recovery-code-oprf-argon2id`) require a vault host POPRF evaluation before Argon2id. A vault whose only slots are pepper slots cannot be opened offline.

## Decision

A SComm writer MUST leave at least one offline slot on every vault it creates: `password-argon2id`, `device-wrap-a256gcm`, or both.

SComm writers MUST NOT create pepper slots. A recovery code, when the user creates one, is a high-entropy secret in a `password-argon2id` slot. The slot type does not change; the secret is not a memorable password and is not sent to a new device during pairing.

Pepper profiles remain specified for other operators. A generic CKVF parser MAY still open a pepper slot when an evaluator is configured. The SComm product profile rejects a vault that has no offline slot rather than calling `vault.scomm.ai`.

No SComm server holds a recovery key. If every device, every CKVF copy, and every offline unlock secret are lost, the payload is unrecoverable.

## Consequences

Discovery availability is not required to decrypt a vault that follows this profile.

Parameter agility stays with the existing Argon2id slot fields (`m`, `t`, `p`, `salt`). Writers keep using the parameters SPEC.md already requires.
