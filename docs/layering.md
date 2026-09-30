# Layering: CKVF vs Discovery

CKVF is the **SComm.AI-maintained** portable encrypted vault **container** (this repo).

Discovery Protocol / `discovery.scomm.ai` (debug port 3000) is the mailbox directory and mailer. It publishes public keys and the armed MSK public key. It does not store vault ciphertext and it is not required to decrypt a container.

SComm does not operate a vault host. The optional vault-host profile remains specified for an operator who runs one. SComm clients synchronize by copying CKVF generations to storage the user controls. See [adr/0001](adr/0001-discovery-hosted-vault-retired.md).

```text
SComm client
  - directory and MSK arming against discovery.scomm.ai
  - CKVF create / open / export on the device
  - optional sync of opaque generations to user-selected storage
  - depends on → ckvf (container bytes only)

ckvf (this repo, scomm-public/ckvf)
  - create / open / export / import vault.ckvf
  - container packages MUST NOT import Discovery HTTP
  - container packages MUST NOT require a vault host to parse or unlock
    a vault that has an offline slot
```

The confidentiality root is the VEK. The MSK authorizes changes. Neither is derived from the other ([adr/0002](adr/0002-vek-is-the-confidentiality-root.md)).

JS and Dart packages in **this** monorepo stay in sync on CKVF test-vectors.
Discovery JS/Dart sync is owned by `sdk_pubkey` + `discovery-protocol` fixtures.

Do not add Discovery Document types, pubkey HTTP clients, or MSK signing to
this repository. That layering is technical, not a claim that CKVF is a
vendor-neutral standards body.
