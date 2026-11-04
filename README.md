# Sahi Chap — Document Signing Platform

Client-held signing keys, PIN-enforced signing, offline-verifiable signatures. This README is the project specification: Sections 1–10 define the protocol, Sections 11–13 define the implementation. Keep them in sync.

**Scope:** Key management, authentication, signing, countersigning, verification. Out of scope for v1: PAdES/embedded PDF signatures, Certifying Authority integration, document-level E2EE, external timestamp authority (slot reserved), key rotation UI, server key rotation, per-tenant policy, per-request MACs, PDF evidence page.

---

## 1. Goals and threat model

### Goals

1. Only the user can produce a signature with their key. The platform cannot forge one.
2. Signing requires a deliberate act (PIN entry) every time, even within a logged-in session.
3. A stolen database reveals no passwords, PINs, or signing keys.
4. Signatures are verifiable offline by third parties, without the platform's cooperation.
5. The platform cannot backdate, remove, or reorder signatures after the fact.
6. Password and PIN can change without changing the user's signing identity.

### Threats defended against

- Database compromise (including all stored records).
- Stolen session/bearer token.
- Unattended logged-in device.
- Network observer (TLS assumed, but design does not depend on it for key secrecy).
- Malicious platform operator attempting to forge or alter signatures.

### Threats NOT defended against

- Fully compromised client (malware reading memory, patched client code). No key-management scheme survives this. Mitigation is a self-hosted SDK for platforms that require it.
- Compromised server clock at the moment of countersigning (bounded by nonce validity; fully mitigated later by an external TSA).
- Legal qualification. Signatures are cryptographic e-signatures with evidentiary weight, not qualified digital signatures under a licensed CA.

---

## 2. Primitives

| Purpose | Primitive |
|---|---|
| Signatures (user and server) | Ed25519 |
| Password and PIN authentication | OPAQUE (RFC 9807), ristretto255-SHA512 suite |
| OPAQUE KSF for password | Argon2id (tuned to ~0.5–1 s on a mid-range phone) |
| OPAQUE KSF for PIN | Argon2id at minimum parameters (8 KiB, 1 iteration, 1 lane); defense is server-side lockout, not client work |
| Key derivation | HKDF-SHA256 |
| Key wrapping | XChaCha20-Poly1305 (AEAD) |
| Hashing | SHA-256 |
| Canonical encoding | RFC 8785 (JSON Canonicalization Scheme) |
| Mnemonic | BIP39, 24 words (256-bit seed) |

All HKDF `info` strings and AEAD associated-data strings are prefixed with `sahichap/` and versioned.

---

## 3. Key material

### Per user

| Name | Where | Description |
|---|---|---|
| `seed` | client only, in memory during signing | 32 random bytes. The sole secret of the signing identity. |
| `sk`, `pk` | derived from `seed` | Ed25519 keypair. `pk` stored on server in clear. |
| `ek_pw` | client only, per session | OPAQUE export_key from password credential. Stable until password changes. |
| `ek_pin` | client only, per signing | OPAQUE export_key from PIN credential. Stable until PIN changes. |
| `sk_pw`, `sk_pin` | client and server, transient | OPAQUE session_keys. Unused in v1 beyond completing the AKE. |
| `KEK` | client only, transient | `HKDF(ikm = ek_pw ‖ ek_pin, salt = "", info = "sahichap/seed-wrap/v1")` |
| `wrapped_seed` | server | `AEAD(key = KEK, nonce = random 24B, plaintext = seed, ad = "sahichap/seed/v1" ‖ user_id)` |

### Per server

| Name | Description |
|---|---|
| `server_sk`, `server_pk` | Ed25519 keypair for countersignatures. Private key in KMS/HSM. Rotation produces a server key-history statement. |
| OPAQUE server setup | OPRF seed and server AKE keys. Stored in KMS, not in the main database. |

### Server-stored user record

```
user_id
opaque_pw_record
opaque_pin_record
pk
wrapped_seed
key_history[]            { pk, valid_from, valid_until | null, rotation_record_id | null }
pin_attempt_count
pin_locked_until
signing_frozen (bool)    admin control
```

Nothing in this record permits recovery of password, PIN, or seed.

---

## 4. Key derivation

```
seed              = random(32)
(sk, pk)          = Ed25519.keypair_from_seed(seed)
mnemonic          = BIP39.encode(seed)

KEK               = HKDF-SHA256(ikm = ek_pw ‖ ek_pin, info = "sahichap/seed-wrap/v1", L = 32)
wrapped_seed      = XChaCha20-Poly1305.seal(KEK, nonce, seed, ad = "sahichap/seed/v1" ‖ user_id)
```

Deriving the keypair from the seed is cheap (one SHA-512, one fixed-base scalar multiplication). Derive on demand at each signing; never persist `sk`.

---

## 5. Authentication flows

All client-side cryptographic operations happen in the client. The server receives only OPAQUE protocol messages, ciphertexts, public keys, signatures, and MACs.

### 5.1 Registration

1. Client generates `seed`, derives `(sk, pk)`, displays mnemonic. User must confirm backup (e.g. re-enter 3 random words).
2. OPAQUE registration with password → server stores `opaque_pw_record`; client obtains `ek_pw`.
3. OPAQUE registration with PIN (6 digits, minimal KSF) → server stores `opaque_pin_record`; client obtains `ek_pin`.
4. Client computes `KEK`, produces `wrapped_seed`.
5. Client sends `pk`, `wrapped_seed`. Server stores all fields and initial `key_history` entry in one transaction.

### 5.2 Login

1. OPAQUE login with password. On success, client holds `ek_pw` in memory for the session.
2. Server issues a session cookie (HttpOnly, Secure, SameSite=Strict) bound to this login.

A logged-in session can browse, upload, and view, but cannot sign.

### 5.3 PIN authentication (per signature)

1. Request must carry a valid session; PIN flow is refused outside an authenticated session.
2. Server checks `signing_frozen` and `pin_locked_until`; refuses if set.
3. OPAQUE login with PIN. The server counts **attempts, not failures**: in OPAQUE the client learns a wrong PIN locally after KE2 and can simply never send KE3, so a failure is invisible to the server.
   - On KE1: increment `pin_attempt_count` atomically before responding. Lockout schedule: 5 attempts → 15 min, 10 → 1 h, 15 → 24 h and notify user.
   - On valid KE3: reset `pin_attempt_count`; client obtains `ek_pin`.
   - Invalid or missing KE3: nothing further; the KE1 increment already counted it. Return generic failure.
4. Server returns `wrapped_seed` together with the `sign_request` (Section 6.2) in the same response. No other server-side state links the PIN auth to the signing request; the `sign_nonce` is that link.
5. Client computes `KEK`, unwraps `seed`, derives `sk`, signs (see Section 6), zeros `seed`, `sk`, `ek_pin`, `KEK`.

`ek_pin` is never retained between signatures.

### 5.4 Password change (old password known)

1. Client holds `ek_pw_old` from the current session.
2. PIN authentication (Section 5.3) → `ek_pin`. Compute `KEK_old`, unwrap `seed`.
3. OPAQUE registration with new password → `ek_pw_new`.
4. Compute `KEK_new`, re-wrap `seed`.
5. Send new `opaque_pw_record` and `wrapped_seed`; server replaces both atomically and invalidates all other sessions.

PIN record unchanged.

### 5.5 PIN change (old PIN known)

1. Client holds `ek_pw`.
2. OPAQUE login with old PIN → `ek_pin_old`. Compute `KEK_old`, unwrap `seed`.
3. OPAQUE registration with new PIN → `ek_pin_new`.
4. Compute `KEK_new`, re-wrap `seed`.
5. Send new `opaque_pin_record` and `wrapped_seed`; server replaces both atomically.

Password record unchanged.

### 5.6 Recovery via mnemonic (password and/or PIN forgotten)

1. User enters mnemonic → `seed` → `(sk, pk)`.
2. Server issues `recovery_nonce`; client returns signature over `"sahichap/recovery/v1" ‖ recovery_nonce ‖ user_id`. Server matches `pk` against `key_history` (must be the current active key).
3. Second factor:
   - PIN remembered: OPAQUE login with PIN required.
   - PIN forgotten: PIN reset permitted after a 24 h cooling-off with notification to all registered channels.
4. OPAQUE registration with new password (and new PIN if reset) → fresh export keys.
5. Compute `KEK`, re-wrap `seed`.
6. Server replaces OPAQUE records and `wrapped_seed` atomically; invalidates all sessions; logs a recovery event.

`pk` unchanged. All prior signatures remain valid.

### 5.7 Key rotation (seed compromised or lost) — protocol reserved, no UI in v1

1. Authenticate via login + PIN, or via recovery (Section 5.6) if the old seed is lost.
2. Client generates `seed_new`, `(sk_new, pk_new)`, new mnemonic.
3. Client produces rotation statement:
   ```
   rotation = { type: "sahichap/rotation/v1", user_id, old_pk, new_pk }
   sig_old  = Ed25519.sign(sk_old, canonical(rotation))   // omitted if old seed lost
   sig_new  = Ed25519.sign(sk_new, canonical(rotation))
   ```
4. Server records `server_time`, countersigns, appends to log. Sets `key_history[old].valid_until = server_time`, adds `key_history[new].valid_from = server_time`.
5. Client re-wraps `seed_new` under current `KEK`; server stores new `pk` and `wrapped_seed`.

Rotation without `sig_old` (lost seed) is flagged as such in the log and in key-history statements.

---

## 6. Document signing

### 6.1 Document lifecycle

1. Upload: server computes `doc_hash = SHA-256(bytes)`, stores file (encrypted at rest; platform-readable), assigns `doc_id`. Document is immutable.
2. Any edit creates a new `doc_id` with `supersedes = old_doc_id`. Signatures never transfer between `doc_id`s.
3. Requester defines a **signing set**: an ordered list of stages, each stage a set of signers with roles and intents, plus an optional deadline.
   - Parallel signing = one stage.
   - Sequential signing = N stages of one signer.
   - Mixed = arbitrary.

### 6.2 Signing request

1. Server issues to an eligible signer (stage currently open, signer in it, not yet signed), as part of the PIN-auth response (Section 5.3 step 4):
   ```
   sign_request = { request_id, doc_id, doc_hash, signer_id, role, intent, stage_index,
                    prev_stage_hash | null, sign_nonce, expires_at (≤ 10 min) }
   ```
   `sign_nonce` is single-use, random, stored server-side with its `request_id`, `signer_id`, and `expires_at`.
2. Client downloads the file, **recomputes `SHA-256` and compares to `doc_hash`**. Mismatch → abort. Client displays the document it hashed.

### 6.3 Manifest

```json
{
  "type": "sahichap/manifest/v1",
  "request_id": "...",
  "doc_id": "...",
  "doc_hash": "sha256:...",
  "doc_size": 12345,
  "signer_id": "...",
  "signer_pk": "ed25519:...",
  "role": "approver",
  "intent": "approve",
  "stage_index": 1,
  "prev_stage_hash": "sha256:..." ,
  "sign_nonce": "..."
}
```

- `prev_stage_hash` is `null` for stage 0. For stage N > 0 it is `SHA-256` of the canonical encoding of the ordered list of record hashes from stage N−1.
- No client timestamp. The only time in a record is `server_time` (Section 6.5); the nonce expiry bounds when the signature could have been made.

```
signature = Ed25519.sign(sk, canonical(manifest))
```

### 6.4 Server verification on submission

Server rejects unless all pass:

1. `sign_nonce` valid, unexpired, issued for this `request_id`/`signer_id`/`doc_id`, not consumed. Mark consumed.
2. `doc_hash` matches stored hash for `doc_id`.
3. `signer_pk` equals signer's current active key.
4. Stage `stage_index` is open and signer has not already signed it. `prev_stage_hash` matches server's computed value.
5. `Ed25519.verify(signer_pk, canonical(manifest), signature)`.
6. Valid session for `signer_id`.

### 6.5 Record and countersignature

```json
{
  "type": "sahichap/record/v1",
  "manifest": { ... },
  "signature": "ed25519:...",
  "server_time": "2026-10-31T10:00:03Z",
  "server_pk": "ed25519:...",
  "log_index": 48213,
  "prev_record_hash": "sha256:...",
  "tsa_token": null
}
server_sig = Ed25519.sign(server_sk, canonical(record))
record_hash = SHA-256(canonical(record) ‖ server_sig)
```

- Records form a single global append-only hash chain across all documents.
- `server_time` is UTC from an NTP-disciplined source; host identity logged separately.
- `tsa_token` reserved for RFC 3161 timestamp.

Chain head (`record_hash` of latest record) is published at least daily to an external anchor (public repository commit and/or blockchain transaction). Anchor publication records are themselves logged.

### 6.6 Completion

When all stages are satisfied, server produces:

```json
{
  "type": "sahichap/completion/v1",
  "doc_id": "...",
  "doc_hash": "sha256:...",
  "record_hashes": ["sha256:...", ...],
  "server_time": "...",
  "log_index": ...,
  "prev_record_hash": "..."
}
```
countersigned and chained like any record.

### 6.7 Evidence bundle

Zip containing:

- original file
- all records with `server_sig`
- completion record
- key-history statements for each signer (server-signed): `{ type: "sahichap/key-history/v1", user_id, pk, valid_from, valid_until, rotation_record_hash }`
- server public key(s) and server key-history
- chain proof: records' `log_index` values, intermediate `record_hash`es to reach an anchored head, the anchored head, and the anchor reference
- `README` with verification instructions and verifier tool link

---

## 7. Verification

Implemented once as a pure function:

```
verify(file, records[], completion, key_history[], server_keys[], chain_proof) → Report
```

Called by both the online endpoint (data from database) and the offline verifier (data from bundle).

Checks:

1. `SHA-256(file) == manifest.doc_hash` for every record.
2. `Ed25519.verify(manifest.signer_pk, canonical(manifest), signature)`.
3. `manifest.signer_pk` appears in a server-signed key-history statement for `signer_id`, and `valid_from ≤ server_time < valid_until` (or `valid_until` null).
4. `Ed25519.verify(server_pk, canonical(record), server_sig)` with `server_pk` valid at `server_time` per server key-history.
5. `record.prev_record_hash` chains correctly; chain proof reaches the anchored head; anchored head matches anchor.
6. For `stage_index > 0`, `prev_stage_hash` equals hash of prior stage's records.
7. Completion record lists exactly these records, is countersigned, and is chained.

Report is structured: per-record pass/fail with reason codes, overall completion status, and warnings (e.g. rotation without `sig_old` in signer history).

Offline verifier ships as a single self-contained HTML page and a CLI. Trust root is `server_pk`, distributed via platform domain, public repository, evidence page, and pinned in the verifier.

---

## 8. Message authentication

| Where | Mechanism |
|---|---|
| Session requests | Session cookie over TLS, Section 5.2 |
| PIN flow gating | Must carry valid session |
| `wrapped_seed` integrity | AEAD tag, with `user_id` as associated data |
| Key derivation | HKDF (HMAC internally) |
| Audit log, timestamps | **Not MAC** — server Ed25519 + hash chain (third-party verifiable) |

---

## 9. Operational requirements

- OPAQUE server secrets and `server_sk` in KMS/HSM, separate from the application database.
- NTP on all signing hosts; log drift; alert on > 1 s.
- `pin_attempt_count` incremented atomically on KE1 (single-row update or Redis `INCR`), not read-modify-write.
- All OPAQUE failures return identical timing and messages.
- Zero sensitive buffers (`seed`, `sk`, `ek_*`, `KEK`) immediately after use on the client.
- Chain anchor publication monitored; missed anchor is an alert.

---

## 10. Reserved for later versions

- `tsa_token`: RFC 3161 timestamp from external TSA.
- PAdES embedding for PDFs.
- Licensed CA integration (Nepal Electronic Transactions Act qualified signatures).
- Document-level E2EE (platform cannot read document contents).
- WebAuthn/passkey as alternative or additional signing factor.
- Shamir-split organizational recovery of `seed`.
- Self-hosted client SDK for platforms requiring protection against operator-served code.
- Key rotation UI (Section 5.7 protocol; `key_history` data model is already in v1).
- Server key rotation: new key signs a statement with old key; both in server key-history; old key's `valid_until` set.
- Per-tenant policy (PIN-reset cooling-off, admin approval).
- Per-request MAC header bound to the OPAQUE session key (`sk_pw`).
- PDF evidence page (human-readable summary, QR to verify URL) appended to a *copy* of the document.

---

## 11. Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Server | Rust, Axum (or Actix-web), Tokio | Learning goal for the project; server workload is light (OPAQUE server half, Ed25519 verify, hashing, DB writes) |
| Database | PostgreSQL via `sqlx` | Compile-time checked queries, explicit migrations, straightforward transactions for atomic multi-record replaces |
| Client | Vite + React + TypeScript | No SSR needed; keeps the client/server boundary sharp |
| Client SDK | TypeScript package | Embeddable by platforms; same code as the web app's auth module |
| Offline verifier | Single self-contained HTML page | Imports the shared TS `verify()`; must run with no network |

### Cryptography libraries

**Rust (server)**

| Need | Crate |
|---|---|
| OPAQUE | `opaque-ke` |
| Ed25519 | `ed25519-dalek` |
| AEAD | `chacha20poly1305` (XChaCha20-Poly1305) |
| KDF / hash | `hkdf`, `sha2` |
| Argon2id (OPAQUE KSF) | `argon2` |
| Canonical JSON | `serde_jcs` |
| Secrets | `zeroize`, `secrecy` |
| Errors / logging | `thiserror`, `anyhow`, `tracing` |

**TypeScript (client, SDK, verifier)**

| Need | Package |
|---|---|
| OPAQUE | `@serenity-kit/opaque` (WASM build of `opaque-ke`) |
| Ed25519 | `@noble/ed25519` |
| AEAD | `@noble/ciphers` |
| HKDF / SHA-256 | `@noble/hashes` |
| BIP39 | `@scure/bip39` |
| Canonical JSON | `canonicalize` |

### Cross-language constraints

1. **OPAQUE suite must match exactly.** `@serenity-kit/opaque` 1.1.0 is built on `opaque-ke` 4.0 with ristretto255 OPRF, `TripleDh<Ristretto255, Sha512>`, base64url-no-pad encoding, and no custom identifiers. The Rust server uses the same suite with `Ksf = Identity`: the KSF runs only on the client, so the server's choice never touches the wire and the client selects Argon2 parameters per credential (`keyStretching` option). Pin both versions. `packages/sdk/src/opaque-spike.ts` against `crates/sahichap-server/src/bin/opaque-spike.rs` is the proof and runs in CI job 3.
2. **Canonical encoding and `verify()` exist in both languages.** They are kept in agreement by the shared test vectors in `vectors/` (see Section 12). Any change to encoding, hashing, or derivation regenerates the vectors in the same commit.
3. **The server never holds client secrets.** Rust code paths that receive `wrapped_seed`, OPAQUE messages, or signatures treat them as opaque bytes. No server code attempts to derive `ek_*`, `KEK`, or `seed`.
4. Argon2id inside the browser WASM is roughly 2–3× slower than native. Tune the password KSF against a mid-range phone and run OPAQUE login in a Web Worker.

### Client code rule

All key material lives in one module (`packages/sdk`) with a small surface: `register`, `login`, `sign`, `changePassword`, `changePin`, `recover`. React components never touch `ek_*`, `seed`, `KEK`, or `sk`. Buffers are zeroed after use (`fill(0)`); JS cannot guarantee this, but it limits exposure windows.

---

## 12. Repository layout

```
repo/
  Cargo.toml              cargo workspace: crates/*
  package.json            pnpm workspace root
  pnpm-workspace.yaml     packages: apps/*, packages/*
  justfile                cross-language commands
  crates/
    sahichap-core/         pure library: canonical encoding, manifest signature verify,
                          record countersign + hash, chain, verify(). Never touches seed,
                          wrapped_seed, or signing. No async, no I/O.
    sahichap-server/       Axum/Actix + sqlx. Depends on sahichap-core.
  apps/
    web/                  Vite + React
    verifier/             single-file offline verifier (HTML)
  packages/
    verify/               pure TS verify(); used by web, verifier, sdk
    sdk/                  TS client SDK: OPAQUE client, keypair from seed, seed wrap/unwrap,
                          canonical encoding, manifest signing. The only place seed and sk exist.
  vectors/                shared test vectors (JSON), generated by Rust, consumed by TS
  migrations/             sqlx migrations
  docker-compose.yml      postgres for local dev
  README.md               this file
```

### Tooling

- **Cargo workspace** for Rust: shared `target/`, one lockfile, `cargo test --workspace`.
- **pnpm workspaces** for JS: `packages/*` linked into `apps/*` without publishing.
- **`just`** as the cross-language runner. Recipes: `dev` (postgres + server + web), `test` (cargo test → pnpm test → OPAQUE integration test), `vectors` (regenerate `vectors/` from Rust), `migrate`.
- **No Turborepo / Nx / Bazel** until the repo is large enough to need caching or orchestration.

### `vectors/`

The contract between Rust and TypeScript. Contains, with fixed keys and nonces:

- manifests → canonical bytes → `SHA-256` → Ed25519 signature
- records → canonical bytes → `server_sig` → `record_hash`
- a short valid chain and several deliberately broken ones (bad hash, bad signature, key outside validity window, wrong `prev_stage_hash`) with the expected `verify()` report

Rust generates the vectors; both test suites consume them; CI fails if either disagrees.

### CI

Three GitHub Actions jobs:

1. `cargo test --workspace` (includes vector checks)
2. `pnpm test` (includes vector checks)
3. Start Postgres and `sahichap-server`, run the JS ↔ Rust OPAQUE round-trip and a full register → login → sign → verify flow.

Job 3 is the gate; the first two can pass while the system is broken.

---

## 13. Build order

0. OPAQUE spike: JS client against the Rust server half, both credentials, export key stable across logins. Done; see Section 11 constraint 1.
1. Crypto half of `packages/sdk` in TS: keypair from seed, wrap/unwrap, canonical encoding, manifest signing. Unit tests with fixed seeds.
2. `sahichap-core`: canonical encoding, manifest verify, record countersign and hash, chain, `verify()`. Generate `vectors/`. Then `packages/verify` in TS passing the same vectors.
3. `sahichap-server`: OPAQUE registration/login for both credentials, attempt-counted lockout, session middleware. The JS ↔ Rust OPAQUE integration test passes here.
4. Documents, signing sets, signing requests, records, chain, completion.
5. `apps/web`: register, login, upload, sign, view status.
6. `apps/verifier`: load bundle, run `verify()`, render report.
7. Chain anchoring, evidence bundle export.

---

## Appendix A — Flow summary

```
REGISTER   seed → (sk,pk) → mnemonic
           OPAQUE.reg(pw) → ek_pw ; OPAQUE.reg(pin) → ek_pin
           KEK = HKDF(ek_pw‖ek_pin) ; wrapped_seed = AEAD(KEK, seed)
           server ← pk, wrapped_seed

LOGIN      OPAQUE.login(pw) → ek_pw ; session cookie

SIGN       request → sign_nonce, doc_hash
           client re-hashes file == doc_hash
           OPAQUE.login(pin) → ek_pin  [server counts KE1 attempts]
           server → wrapped_seed + sign_request
           KEK → seed → sk → sign(manifest) → zero
           server verifies, countersigns, chains

VERIFY     file hash → signer sig → key valid at server_time
           → server sig → chain → anchor → completion
```

## Appendix B — Why these choices

- **Seed-derived Ed25519 over stored private key:** the seed is the whole secret; keypair derivation is free; recovery is a mnemonic.
- **OPAQUE for PIN, not SRP or hashed PIN:** a 6-digit space has ~20 bits of entropy. Only a design with no offline attack (server-held OPRF key) and a server-counted guess is defensible. SRP verifiers and salted hashes are offline-attackable regardless of KSF cost.
- **KEK from both export keys:** PIN is enforced cryptographically, not by a client-side check that can be skipped. Password and PIN are independent credentials, so each can change without the other.
- **No server-held share:** `ek_pin` already has every property a share would provide, and the server never holds it.
- **Server time, not client time:** the signer has an incentive to lie about time; the server is the only disinterested party in v1. Hash chain + anchors prevent the server from revising history.
- **Manifest with nonce and request_id:** a signature on a bare hash can be replayed into a different workflow. Binding role, intent, request, and nonce makes each signature mean exactly one thing.
- **Pure-function verifier shared by online and offline paths:** guarantees the bundle is self-sufficient and that the platform's claims survive the platform.
