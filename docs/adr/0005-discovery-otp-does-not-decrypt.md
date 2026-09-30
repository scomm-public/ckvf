# 0005. Discovery recovery and Vault recovery are separate

## Status

Accepted

## Context

Mailbox OTP arms the first MSK or replaces a lost MSK on Discovery. That proof shows control of the mailbox. It is not an input to the VEK wrap.

## Decision

Discovery recovery MAY replace the directory MSK using the existing mailbox OTP flow.

Vault recovery MUST use one of:

- an authorized device that already holds a device KEK
- a CKVF container plus an offline unlock secret (password or recovery code in a `password-argon2id` slot)
- a supported platform keystore that still holds the device KEK

OTP, a Discovery grant, or an MSK public key MUST NOT unwrap a VEK.

Replacing the MSK because the mailbox was recovered does not decrypt historical vault payloads. Those payloads open only with a remaining slot.

## Consequences

Clients must say this in recovery UI. They must not generate a fresh key set while leaving the previous Discovery keys active and pretending the old private keys were restored.
