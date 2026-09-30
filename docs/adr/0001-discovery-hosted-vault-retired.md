# 0001. Discovery stays hosted; SComm does not host Vault ciphertext

## Status

Accepted

## Context

CKVF is a portable encrypted container. A separate vault-host profile describes an optional HTTP service that stores opaque containers and evaluates pepper OPRF. SComm also operates Discovery, which publishes public identity and key material.

Operating both a directory and a ciphertext store on SComm infrastructure makes Vault look like a hosted product, and it makes pepper slots undecryptable without that host.

## Decision

SComm Discovery remains the hosted public directory and mailer.

SComm does not operate a Vault service. `vault.scomm.ai` is not required to create, unlock, export, import, or synchronize a SComm vault.

The vault-host profile stays in the specification for an operator who chooses to run one. It is not the SComm product path.

Discovery MUST NOT gain upload, download, backup, or sync routes for vault ciphertext.

## Consequences

Clients keep private material in a CKVF container on the device and, if the user opts in, on storage the user controls.

A stolen or compromised Discovery deployment does not yield a VEK.

Production DNS, databases, and secrets for a former vault host are retired by operators, not by this specification.
