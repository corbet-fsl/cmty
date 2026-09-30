# cmnt

Community admission for cvld, composed over cmbr, cgts and cplc.
Native Rust, development API, FSL-1.1-ALv2; no registry publication.
See the [implemented contract](docs/CONTRACT.md).

`Community::begin` signs a single-use passport request for the wallet's selected
community origin. `verify` delegates the real proof to cgts/cpsd. `finish` binds
that witness to the current passkey, collects checked gates, asks cplc, commits
cmbr admission and returns cplc's Ed25519 COSE credential. cplc is the sole
admission decision owner; cmnt contains no policy or lifetime implementation.

Construct `Parts` from the real three facades on one shared crlt database.
Configure cmbr/cplc with `community.admit`. Give the wallet `signed_request()`;
retain the challenge on the server. First registration consumes a verified
passport and then completes WebAuthn, handle reservation and v2 pins through
cmbr. Every admission/renewal needs a fresh presentation and real authentication.
The caller supplies authorized device keys and a bounded lease, never standing.

crbk settings default to one-day new credentials, thirty-day established
credentials and fourteen-day probation. cmbr stores standing; cplc caps expiry
at gate/passport, lease, signer and policy limits. The lobby is read-only and
carries the expiry and second-device warnings. Expired registration or loss of
all passkeys permanently prevents rejoining this community: **NO RETURN**.

Call `flush_revocations` after membership revocation/maintenance and distribute
the published epoch; `begin` also drains pending events. Authenticate cglb's
public status before `update_passport_policy`; changed global epochs reject old
passports and prevent suspended holders from renewing community credentials.
Slow gate checks run outside the policy mutex. Each facade retains its own
per-member/CAS failure handling. No credential, login history or raw gate data
is stored here.

Append cmbr's complete schema set plus cgts, crbk, cplc, csgn and cmnt's cpsd
challenge schema once to the shared migration history. Every dependency is pinned
by full revision and CI rejects a second Corbet revision in the resolved lock.

## Dependency survey

Rechecked GitHub main manifests/APIs and crates.io documentation on 2026-09-30
before the recomposition. Every direct cvld dependency is pinned by full revision
in `Cargo.toml`.

| Candidate | Choice and reason |
|---|---|
| [cmbr](https://github.com/corbet-libs/cmbr), [cgts](https://github.com/corbet-libs/cgts), [cplc](https://github.com/corbet-libs/cplc) | Required domain owners. Compose their ready APIs directly; delete local ports, policy evaluation and lifetime calculation. |
| [cpsd](https://github.com/corbet-foss/cpsd) | Existing BBS verification, community pseudonyms and atomic replay protection; no copied challenge/crypto logic. |
| [crlt](https://github.com/corbet-foss/crlt), [official libsql](https://docs.rs/libsql/) | crlt is ready and supplies the scoped shared database, migrations and index enforcement. No driver fallback or ORM. |
| [crbk](https://github.com/corbet-foss/crbk), [csgn](https://github.com/corbet-foss/csgn) | Shared protocol types and COSE verification; decisions/signing execute through cplc. |
| [Casbin](https://github.com/apache/casbin-rs), [Cedar](https://github.com/cedar-policy/cedar) | Maintained general authorization engines; redundant with the existing crbk/cplc owner and do not supply this composition. |
| [coset](https://github.com/google/coset), [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | Established primitives already behind csgn. dalek is also test-only for synthetic legal authority signatures. |

Serde/serde_json provide typed views, thiserror redacted errors, Tokio
serialization and chrono authoritative time validation. Tests use tempfile and
a real software WebAuthn authenticator. Facades retain FSL; selected leaves retain
their LGPL linking exception. No GPL/AGPL-only dependency is added.

## Validation and current limits

GitHub Actions runs formatting, Clippy, real integration tests and dependency
checks. Cargo is never run on the workstation. Tests cover BBS, WebAuthn, pins,
probation, expiry, replay, policy changes, revocations, suspension and restart.
Optional Turso tests require both `TURSO_URL` and `TURSO_TOKEN` for an explicitly
authorized disposable database.

Unproven cblc extensions remain disabled and pin changes fail closed. Admission
can commit before a signing failure; retries use fresh presentations. Services
own canonical routing, session expiry, device-key authorization, authenticated
policy distribution and rate limits. Offline consumers need current epochs and
revocations in addition to signature verification.

Licensed under the [Functional Source License](LICENSE.md).

For a running service, `refresh_passport_policy` also replaces the authenticated
configuration deadline after the service verifies a fresh signed global status.
It rejects expired deadlines and epoch rollback, serializes with issuance and
invalidates challenges bound to the previous configuration. The service retains
durable public revision/epoch floors and authorizes issuer-key installation.
