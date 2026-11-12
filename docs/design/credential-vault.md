# Credential vault crypto

The exact cryptography behind CLI logins: how the control plane stores
credential values, how hosts return captured values, and the feature gate.
This document is the specification. The code implements it in
`packages/api/src/credentials/vault/` (TS, the control plane) and
`apps/cli/src/sandbox_relay/credentials/` (Rust, the node daemon). Section 4 of
the CLI-logins plan is the design source.

Every key, scalar, and nonce below is a fixed **test** value. None is used
anywhere outside tests.

## Threat model summary

- **DB dump only.** Values are AES-256-GCM under a fresh per-value DEK. Each
  DEK is wrapped under a single-use key derived from an env-only root with a
  fresh 256-bit salt. Nothing stored lets anyone check a guess of the root
  offline: there is no MAC over plaintext and no key check value.
- **DB write without the key.** The AAD binds every value to its owner, login,
  instance, storage sequence, kind and `policyDigest`. A row or wrapped DEK
  moved anywhere else fails authentication. Return-key rows bind the public key
  to the wrapped private key, and every load re-derives the public key.
- **Out of scope.** Control-plane compromise (process, env, Valkey). Coherent DB
  rollback: AAD stops transplanting, not freshness. Plaintext remanence beyond
  best-effort zeroing (see [Memory hygiene](#memory-hygiene)), including guest
  disks after a scrub (an offloaded disk carries them, see
  [Whole-disk offload](#whole-disk-offload)). The product-level threat model is in the
  [CLI logins guide](../guide/cli-logins.md#security-model).

## Key hierarchy

```
DATA_ENCRYPTION_KEY (root, 32 bytes as 64 lowercase hex; kid = hex(SHA-256(root))[0:16])
 ├─ K_wrap  = HKDF-SHA256(ikm=root, salt="wssp-data-key-v1", info="cred-dek-wrap:v1", 32)
 ├─ K_rwrap = HKDF-SHA256(ikm=root, salt="wssp-data-key-v1", info="cred-return-key-wrap:v1", 32)
 └─ webhook-endpoint-secret:v1 (unchanged)

Per stored value:     DEK    = 32 random bytes, used for exactly one encryption
Per DEK wrap:         K_row  = HKDF-SHA256(ikm=K_wrap,  salt=wrapSalt (32 random),  info="wssp:cred-wrap-row:v1", 32)
Per private-key wrap: K_rrow = HKDF-SHA256(ikm=K_rwrap, salt=rwrapSalt (32 random), info="wssp:cred-return-key-row:v1", 32)
Return keypair:       X25519; kidR = hex(SHA-256(publicKey))[0:16]
```

Both purpose labels are in `DATA_KEY_PURPOSES`
(`packages/api/src/crypto/data-key.ts`). A label is part of the derivation and
is never renamed. Rows store the **root** kid. `DATA_ENCRYPTION_KEY_PREVIOUS`
supplies the second root during a rotation. Which root new rows use is decided
by the database epoch, not by the env (see [Rotation](#rotation)).

**Usage accounting.** Each DEK encrypts one plaintext. Each `K_row` and `K_rrow`
encrypts one key under a fresh salt. No long-lived key performs GCM
encryptions, so there is no aggregate nonce budget to track. That holds across
rotations, retries, and rewraps too: a rewrap draws a new salt and nonce.

## Encodings

- **AAD lists** use `encodeHmacContext`: `LP(x) = u32be(len(UTF-8(x))) ‖ UTF-8(x)`,
  concatenated. Every field is a string.
- **Identifiers** inside an AAD are non-empty, at most 256 UTF-8 bytes, and
  well-formed. TS refuses lone surrogates. Rust strings are always valid.
- **Sequences** (`storageSeq`, `captureSeq`) are integers in `[1, 2^63 − 1]`,
  written as their shortest decimal string (`"7"`, never `"07"`).
- **Digests** (`definitionDigest`, `policyDigest`, `recipientPubSha256`,
  `sealedSha256`) are 64 lowercase hex characters. Kids are 16 lowercase hex.
- **X25519 public keys** travel as unpadded base64url, exactly 43 characters,
  and must re-encode to the same text. That rule refuses padding, the `+`/`/`
  alphabet, and non-zero trailing bits. The decoded u-coordinate must be
  canonical: high bit clear and less than p = 2^255 − 19. Both libraries would
  otherwise reduce several encodings to the same point.
- **All-zero DH.** An X25519 result of all zeros is refused (RFC 9180 §7.1.4,
  RFC 7748 §6.1). That covers every low-order point: 0, 1, p − 1, and the two
  order-8 points. Node/OpenSSL and ring each refuse it, and both
  implementations check it again explicitly.
- **Private keys** are raw 32-byte scalars, clamped by the curve operation.

## Stored value

```
policyDigest = hex(SHA-256('{"definitionDigest":"<64 hex>","delivery":"GUEST|PROXY"}'))

ciphertext ‖ tag = AES-256-GCM(DEK, nonce (12 random), plaintext,
  AAD ["wssp:cred-value:v1", userId, credentialId, instanceId, storageSeq, kind, policyDigest])

wrappedDek (48) = AES-256-GCM(K_row, wrapNonce (12 random), DEK,
  AAD ["wssp:cred-dek:v1", rootKid, userId, credentialId, instanceId, storageSeq, policyDigest])
```

`kind` is one of `UPLOAD | LOGIN | CAPTURE | CHECKPOINT | RECOVERY | PROMOTED | REPIN`.
The vault owns these `CredentialSecretVersion` columns: `ciphertext`
(ciphertext ‖ tag), `nonce`, `wrappedDek`, `wrapSalt`, `wrapNonce`, `rootKid`,
`policyDigest`, and `sizeBytes`.

**Decrypt.**

1. The caller rebuilds the context from authoritative rows. It recomputes
   `policyDigest` from the verified definition and delivery.
2. Refuse `context_mismatch` if the row's stored digest differs.
3. Pick the sub-key whose root kid equals `rootKid`. If none matches, refuse
   `key_unavailable`.
4. Derive `K_row`, unwrap the DEK, and decrypt.
5. Check `sizeBytes`.
6. Zero the DEK and `K_row`. The plaintext belongs to the caller, who zeroes it.

**Rewrap** unwraps the DEK and wraps it again under the new root's `K_wrap`
with a new salt and nonce. The value ciphertext does not change.

There is no stored MAC. To detect an unchanged value, decrypt the current value
and compare in memory.

## Return keys

```
wrappedPrivate (48) = AES-256-GCM(K_rrow, wrapNonce (12 random), privateKey,
  AAD ["wssp:cred-return-key:v1", rootKid, kidR, base64url(publicKey)])
```

Every wrap and rewrap draws a fresh `rwrapSalt` and nonce. On every load the
server decrypts the private key, derives its public key, and refuses
`return_key_mismatch` unless the derived key equals the stored `publicKey` and
`kidR = hex(SHA-256(publicKey))[0:16]`. The AAD already refuses a swapped
column. The derivation check refuses a writer who could wrap a key for a
different public key.

The return-key **epoch**, issuance, rotation, and destruction rules
are row and protocol logic (`packages/api/src/credentials/return-keys.ts`). This
crypto core has no epoch field. Destruction overwrites `wrappedPrivate` with
zero bytes. A rewrap never selects a destroyed key, so it stays empty.

## Rotation

Root-key rotation uses a database write fence, shared with webhooks
(`packages/api/src/crypto/data-key-epoch.ts`):

- The singleton `data_key_epoch {currentKid, previousKid, epoch, switchedAt}`
  names the kid every encrypted writer must seal under. Each writer runs
  `SELECT … FOR SHARE` on it inside its own transaction: value inserts, the DEK
  and return-key rewrap, return-key creation, and the webhook create, rotate
  and rekey. A writer that does not hold that root aborts with retryable
  `data_key.stale_writer` before it writes anything. The first writer inserts
  the row with its env current kid.
- `promoteDataKey` (`pnpm data-key:promote <kid>`, admin card) takes the row
  `FOR UPDATE`. It waits for in-flight writers. After it commits, no
  transaction can commit a row under the old kid. It refuses a kid the
  promoting process does not hold.
- The rewrap (`credentials/rewrap.ts`) runs in the worker's 60 s maintenance
  tick. It takes batches of 200 `FOR UPDATE SKIP LOCKED` rows whose
  `rootKid` is not the epoch's, behind an in-memory keyset cursor that wraps.
  DEKs are rewrapped with a new salt and nonce, and the value ciphertext is
  untouched. Live return private keys get a new `rwrapSalt` and nonce, and
  the public key is re-checked on unwrap. Each update re-checks the old kid.
- Status (`crypto/data-key-status.ts`) counts rows per kid for every registered
  column: webhook `secretKeyId` and `previousSecretKeyId`, vault versions, and
  live return keys. `safeToRemove(old)` holds when the epoch's kid is not `old`
  and every count for `old` is 0. Valkey heartbeats `{role, keysHeld}` (30 s,
  TTL 120 s) are advisory only.

The operator runbook is in
[production hardening](../operations/production-hardening.md#data-encryption-key).

## Sealed box

The host seals with Rust `ring`. The server opens with Node `crypto`.

```
seal   = eph_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)          (overhead 60 bytes)
shared = X25519(eph, recipient_pub)                               (all-zero refused)
key    = HKDF-SHA256(ikm = shared, salt = eph_pub ‖ recipient_pub,
                     info = "wssp:cred-return:v1" ‖ kidR (16 ASCII hex), 32)
AAD    = LP ["wssp:cred-return:v1", kidR, serverOrigin, hostOwnerId, hostId,
             sandboxOwnerId, sandboxId, leaseId, bindingId, instanceId,
             credentialId, captureSeq, captureId, kind, residueId | ""]
```

- `kind` is the lowercase capture-kind token `^[a-z][a-z0-9_-]{0,31}$`, for
  example `stop`, `checkpoint`, `recovery`, or `login`. `residueId` is `""`
  unless the capture packs a residue.
- The AAD contains no sandbox generation. The binding authorizes a capture.
- Every seal uses a fresh ephemeral key. The derived key and nonce are
  therefore never reused.
- The server opens with an AAD it **rebuilt from rows**, never one read from
  the envelope header.

## Envelope

```
"WSCO" ‖ u8 version = 1 ‖ u32be headerLen ‖ header JSON (≤ 4096 bytes) ‖ seal

header = {"kidR":…,"recipientPubSha256":…,"aad":{serverOrigin, hostOwnerId, hostId,
          sandboxOwnerId, sandboxId, leaseId, bindingId, instanceId, credentialId,
          captureSeq, captureId, kind, residueId},"sealedLen":N,"sealedSha256":…,"createdAt":ms}

envelopeDigest = SHA-256(all envelope bytes) = SHA-256(header bytes ‖ seal)
```

**Header rules.**

- The header has exactly one accepted spelling: compact JSON in the key order
  above, as serde writes it.
- Every AAD field is a JSON string, including `captureSeq`.
- `createdAt` is integer Unix milliseconds, at most 2^53 − 1. It is advisory
  and never authorizes anything.
- `kidR` must equal the first 16 hex characters of `recipientPubSha256`.
- `sealedLen` must equal the seal's length, and `sealedSha256` its SHA-256.
- A parser refuses whitespace, reordered or duplicate keys, unknown keys,
  numeric sequences, oversize headers, and trailing or missing bytes.

**Digest.** "Header bytes" means the whole prefix before the seal: magic,
version, length, and JSON. The server ledgers this digest and matches replays
on `(captureId, envelopeDigest)`.

**Opening.** The opener checks the steps below in order and refuses
`context_mismatch` on the first failure, before it uses any key:

1. The header names the server's return key: its `kidR` and
   `recipientPubSha256` match that key.
2. Each header AAD field equals the server-rebuilt value.

It then opens the seal with the rebuilt AAD.

## Memory hygiene

- **Server.** Plaintext and key `Buffer`s live only inside
  `credentials/vault/`, plus callers that zero them in `finally`. DEKs,
  `K_row`, `K_rrow`, shared secrets, and HKDF outputs are zeroed before the
  vault returns. Errors are `CredentialVaultError` with a fixed code and
  message, never data.
- **Host.** `SecretBytes` wraps `zeroize::Zeroizing<Vec<u8>>`. It has no
  `Clone`, `Serialize`, or `Display`, and its `Debug` prints only the length.
  Growth moves into a fresh zeroizing buffer, so a reallocation never leaves an
  unwiped copy.
- **Not covered.**
  - The shared secret inside `ring`, which ring does not zeroize.
  - Kernel copies.
  - Swap.
  - `mlock`. It needs `unsafe`, which the crate forbids.

  The daemon calls `prctl(PR_SET_DUMPABLE, 0)` at start-up (`harden_process`,
  `apps/cli/src/sandbox_relay/credentials/secret.rs`). Operators should set
  `LimitCORE=0` and use encrypted swap or no swap.

## Whole-disk offload

A stopped sandbox's root disk can move to the image store and resume on
another eligible host ([sandboxes](../guide/sandboxes.md#disk-offload)). A
disk that once held CLI-login files is offloaded too. This section is the
exception to "the daemon never writes a login value outside the guest": the
export is the whole root volume, so it carries any login file the guest
holds and any freed block that once held one.

**Key hierarchy.** Disks do not reuse the template image master key, and
`IMAGE_STORE_ENCRYPTION` has no effect on them.

```
DATA_ENCRYPTION_KEY (root)
 └─ K_diskwrap = HKDF-SHA256(ikm=root, salt="wssp-data-key-v1", info="sandbox-disk-dek-wrap:v1", 32)

Per upload session: DEK   = 32 random bytes; encrypts one staged export (aes256gcm-r1 records)
Per DEK wrap:       K_row = HKDF-SHA256(ikm=K_diskwrap, salt=wrapSalt (32 random), info="wssp:sandbox-disk-row:v1", 32)
Wrap:               AES-256-GCM, random nonce,
                    AAD = encodeHmacContext("wssp:sandbox-disk-dek:v1", rootKid, userId,
                                            sandboxId, offloadId, seq, sessionId)
```

- Every upload session draws a fresh DEK, so two exports never share a key.
  A retry after a lost staging file uses a new offload id and a new key.
- The session id is generated before the wrap, so it is bound in the AAD. A
  wrap copied to another sandbox, offload or session fails to unwrap.
- A session holds the wrap only while it is open. Completing the upload
  moves the wrap to the offload row and clears it from the session in the
  same transaction; supersede and abort clear it too.
- Wrap writes take the data-key epoch like vault writers, and
  [Rotation](#rotation) rewraps live offload rows. `pnpm data-key:status`
  does not report `safeToRemove` for a root kid while an unshredded disk
  wrap or an open disk upload session still uses it.
- **Shred** zeroes the offload row's `wrappedKey`, `wrapSalt` and
  `wrapNonce` and stamps `shreddedAt`. One function does it, always before
  the object is deleted: at once for a failed or superseded offload, when
  the consumed grace passes after a resume, and after
  `SANDBOX_OFFLOAD_SHRED_GRACE_HOURS` for a destroyed sandbox. No admin view
  or projection reads the wrap columns.
- **Delivery.** The DEK reaches a daemon only in the `encryption` field of
  one upload or fetch grant, for one transfer. It never appears in outbox
  rows, receipts, events, webhooks, logs or the daemon journal, and the
  daemon holds it in zeroizing buffers.

**Gates.**

1. **Settled state only.** Offload is refused, at enqueue, at upload begin
   and again before the copy is marked stored, while any login lease of the
   sandbox is outside `RELEASED`, `FORCE_RELEASED` or `ABANDONED`, while a
   recoverable residue has a newest value not yet in the vault, or while a
   capture-back is pending. A value is therefore never lost or duplicated by
   a move. This is a recovery-state check, not a proof the disk is clean.
2. **Encrypted before it leaves the host.** The server never issues a disk
   grant without `encryption`, and the daemon refuses one. The store, the
   relay and any proxy see only ciphertext.
3. **Own hosts at resume.** The first login grant for a sandbox (guest
   files, guest env or proxy) sets a permanent login-history flag. It is
   never cleared, not even when the login is deleted, and it restricts every
   later restore to hosts you own. Attached logins still need
   `credential.host_forbidden` clearance at every start.
4. **Short-lived plaintext on the source host.** `incus publish` and the
   export write the whole root, plaintext and block-level, into the host's
   Incus image store and daemon staging. Both are deleted once the server
   confirms the copy is stored, on failure or supersede, and by the start-up
   sweep after a crash; the 24-hour staging sweep is the backstop. They add
   no reader the root volume on that host did not already have. A restore
   host decrypts into its own staging, imports, and deletes the image right
   after the VM is created.
5. **Managed sandboxes** (template builds) are never offloaded.

**Residual risks.**

- **The control plane holds the key.** Anyone with control-plane compromise
  (the process or its environment, or the database plus the root key) can
  decrypt an offloaded disk, including login files and freed blocks.
  Coherent database rollback stays out of scope, as for the vault.
- **With guest sudo, no in-guest scrub is trusted.** On a sandbox with guest
  sudo (the default) or any guest-root lineage, a root guest may have copied
  login values anywhere, and every scrub report comes from guest binaries.
  An offloaded disk is treated as possibly holding every value it ever saw.
  Only encryption, own-host resume and lease settlement protect it.
- **Remanence travels with the disk** to your other hosts.
- **The source host's plaintext copies** exist until the upload is
  confirmed, under the exception in gate 4.
- **Backups.** Shredding a wrap does not reach database backups taken
  before it. A shredded disk stays decryptable from such a backup, with the
  root key, until the backup ages out
  ([backup and restore](../operations/backup-and-restore.md#disk-offload)).

## Feature gate

`CREDENTIALS_ENABLED` is a shared boolean that defaults to `true`. It is a
turn-off switch: optional features are on by default
(`packages/api/src/credentials/availability.ts`).

| `CREDENTIALS_ENABLED` | `DATA_ENCRYPTION_KEY` | State                                                                                                                                                                                                                                                                                           |
| --------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| unset / `true`        | set                   | **Enabled.** `/v1/capabilities` lists the features `credentials.read`, `credentials.write` and `credentials.use`.                                                                                                                                                                               |
| any                   | unset                 | **Unavailable.** Boot never fails. Entry points refuse with `credential.unavailable` (400). The dashboard's Logins page says logins are not available; the admin data-key card names the missing `DATA_ENCRYPTION_KEY`. Captures that arrive with data present ack `DEFERRED`.                  |
| `false`               | set                   | **Drain.** New use (create, upload, attach, sign-in, settings) refuses with `credential.unavailable`; the Logins page is read-only. Reads, capture commit, census, free, force-release, discarding rejected captures, finishing or cancelling a login session, delete, and rewrap keep working. |

`pnpm generate:secrets` always generates `DATA_ENCRYPTION_KEY`. The Dokploy
checklist lists it under set-once variables and lists `CREDENTIALS_ENABLED` as
optional, so a standard deploy has logins on. The gate is
`readCredentialsAvailability` / `requireCredentials`
(`packages/api/src/credentials/access.ts`).

## Test vectors

All values are test-only.

**Sub-keys.** For the root
`a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90` (kid
`6685009530c3e0f4`):

| Purpose                      | Sub-key                                                            |
| ---------------------------- | ------------------------------------------------------------------ |
| `cred-dek-wrap:v1`           | `9f211b9d0c69591e3206187be83973ad10d16440f153b460ca540d02dd9f47ce` |
| `cred-return-key-wrap:v1`    | `d164bf65e41d2e194bd63850abe6cb9174be5df98aa4672a7f6e1a764105069c` |
| `webhook-endpoint-secret:v1` | `350d4d1a30a8d76f82963339bf74b6d6893d670956e00444900a30e656cbae06` |

**Single-use row keys.** With salt `00 01 … 1f`:

- `K_row = 471814d25e72191cb2a8edd66830490f190ce3e5cfbd2670121b717ea0e9fe3b`
- `K_rrow = b1bc2a220764fdfe5d79e577955932a21ff5b62018892f5897d69c368b784fbd`

**Policy digest.** `definitionDigest = "ab" × 32` with `delivery = GUEST` gives
`7d3f4153cd06937f36b5c93972757c5c5b3612dd5d3c8d37358a3236f2bedc06`.

**Stored value.** Context: user `usr_1`, credential `crd_1`, instance `cin_1`,
`storageSeq` 3, kind `UPLOAD`, the policy digest above.

| Input     | Value                   |
| --------- | ----------------------- |
| DEK       | `0x11` × 32             |
| nonce     | `0x22` × 12             |
| wrapSalt  | `0x33` × 32             |
| wrapNonce | `0x44` × 12             |
| plaintext | `{"token":"test-only"}` |

| Output           | Value                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------- |
| ciphertext ‖ tag | `6cd57326abaaf17ddf1daa593bd2c4ba71ffb4c017105f03ab9bdb26b498e5d5d1a1158494`                       |
| wrappedDek       | `953595d897a4b3d1db7522ab11afbf45210a7c3ed98ce4671e289647ea3c1620ba661f9ba77611e12327c38d4cabe585` |

**Return key.**

| Input       | Value       |
| ----------- | ----------- |
| private key | `0x55` × 32 |
| rwrapSalt   | `0x66` × 32 |
| wrapNonce   | `0x77` × 12 |

| Output         | Value                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------- |
| public key     | `38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67`                                 |
| kidR           | `1128de8a3d96a514`                                                                                 |
| wrappedPrivate | `f4817521580b8194df186a3238e19289d98dd3853b906dc361cf831ae3ea8c023f90b46a49532bbf943717ae3e06ae79` |

**Sealed box and envelope.** The full set is
`packages/api/src/credentials/vault/fixtures/seal-v1.json`. It holds three cases
(empty plaintext, a small bundle, and a UTF-8 recovery capture with a residue
and the maximum `captureSeq`), plus the invalid and low-order public keys. The
`empty-plaintext` case:

| Field                 | Value                                                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| recipient private key | `1379d058b0d56941d0ffa8f5f9311c5fc25bcbb8ca90549485cc54e59cef5359`                                                                                                  |
| recipient public key  | `4sSNGdGalLVv8ZvCANjgzb9ziy5IuGCY1DZyNvniwGM`                                                                                                                       |
| kidR                  | `46a3b223535835a1`                                                                                                                                                  |
| ephemeral private key | `4ae715667e27a284399e6f566c5ef1cf84af7ae605db7dd14b448c088325cd30`                                                                                                  |
| nonce                 | `be540c9f24abcae5c260b96f`                                                                                                                                          |
| seal                  | `fbf34890950a5bd3ae5635c43e4cc20f42630f94d87b1ed379b5642287410a76` `be540c9f24abcae5c260b96f` `7382dd1ff617fdb5aef8490e0ad8e462` (ephemeral public key, nonce, tag) |
| envelopeDigest        | `58a77c41b3fd9e6d890aff9f08bb301160ec6afb8155c56cf932a5e5183a46db` (`createdAt` 1793700000000)                                                                      |

**How the vectors are checked.**

- TS and Rust both reproduce every seal and envelope byte for byte from the
  same ephemeral key and nonce, and both open them. The Rust opener is
  test-only.
- An independent Python `cryptography` implementation reproduced the stored
  value, return key, and seal values when the vectors were made.
- The negative tests cover:
  - a change to any AAD field
  - a wrong recipient, kidR, or root kid
  - truncation and bit flips
  - non-canonical keys and headers
  - low-order points
  - a wrapped-DEK transplant
  - a substituted return public key
  - fresh salts on every wrap and rewrap
