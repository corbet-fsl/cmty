# cmty implemented contract

Community composition under `cvld → cmty`, over cmbr, cgts and cplc. Native Rust,
FSL-1.1-ALv2, development API. No cryptography, policy evaluator, membership state
machine, lifetime calculator, gate adapter or signing store is implemented here.

## Ownership and verified inputs

cplc alone decides admission through crbk over its authenticated settings and
cgts's bound `CheckedGates`. cmbr owns passkeys, enrolment, handles, v2 pins,
probation and membership leases. cgts owns gate verification, retained facts,
action-bound receipts and the unconditional legal veto. cpsd owns blind passport
proofs, authenticated wallet requests and atomic replay prevention. csgn owns
COSE signing; crlt owns database capabilities and indexed transactions.

`Parts` contains the actual three facades. Configure cmbr and cplc with
`community.admit`, one canonical community and one shared database. The optional
`SharedRulebook` adapter shares an actual crbk store; cmty never resolves it or
calls crbk's decision function. `PolicySnapshot` is a read-only UI view, not an
admission capability. Caller-built snapshots, pseudonyms and raw gate metadata
cannot substitute for verified admission inputs.

`begin` returns a server-held challenge. Send `signed_request()` to the wallet.
The wallet verifies the COSE request against the authenticated keys of its
selected community origin before presenting. Unsigned requests cannot be passed
to cpsd's wallet API. `verify` delegates to `cgts::verify_passport`, consuming the
actual cpsd challenge and producing an opaque witness. `begin_registration`
consumes that witness at the same trusted time and starts cmbr's WebAuthn flow.
The community-local UUID is service-generated; the member identity is the real
community pseudonym. Registration alone grants no access.

`finish` requires a fresh proof plus a real ckyh authentication, authorized public
device keys and a coarse lease. It checks the authentication's current passkey
and pseudonym. No caller-supplied membership class exists. `finish_with` can run
additional checks through the real cgts instance. Each receipt binds community,
subject, action, exact settings content/publication, effective epoch and time.
Global facts come only from cgts's verified passport witness. cgts checks legal
state and combines fresh and retained facts; cmty never manufactures gate results.

cplc validates the current verified settings and makes the decision. A negative
explicit admission attempt delegates lapse to cmbr and returns `Missing`.
A legal veto returns `Vetoed`; failures are errors. Merely calling the cmbr lobby
or cmty `snapshot` does not mutate membership or publish anything. On allowance,
cmbr commits admission, and cplc issues while holding cmbr's per-member source
lease. Pending, lapsed, released, legally restricted or unacknowledged-revocation
members cannot obtain a credential even under a gate-free policy.

The wire payload is `cplc::Credential`. cmty verifies it through csgn and returns
a `CredentialClaims` view. Global gates, global identifiers, proof times and
passport bytes never enter this credential. Pin values and salts remain on the
device; only context-bound v2 fingerprints enter permanent community storage.

## Lifetimes, no return and revocation

crbk settings supply the defaults: one day for new members, thirty days for
established members, fourteen days of probation. cmbr stores the probation end
at UTC-day granularity, never resets it on renewal and deletes it once passed.
cplc derives standing from that stored state and caps issuance at current gate
and passport expiry, membership lease, signer limits and announced activation.
cmbr bounds service-selected leases to its configured maximum of 1–24 months.
Stored and signed membership times are day-rounded. Short single-use protocol
challenge deadlines remain precise (at most five minutes); announced policy
cutoffs retain protocol precision. No login time or request history is stored.

**NO RETURN:** registration expiry and loss/revocation of all passkeys permanently
prevent the same person from rejoining this community. A new UUID does not evade
the pseudonym tombstone. Burned global uniqueness fingerprints never become
available to another person. The cmbr lobby warns before registration expiry and
recommends a second device or synced passkey when only one key is registered.
Every authenticated operation rechecks the exact passkey; a revoked key's saved
session stops working immediately.

Membership changes create a durable generation-tagged revocation outbox.
`flush_revocations(now)` advances cplc's community epoch, publishes settings and
revocations, then acknowledges the observed generations. Signing/publication
failure leaves events pending. A crash may repeat the conservative epoch bump;
it cannot acknowledge an unpublished revocation. `begin` also drains a bounded
batch. The service must call/drain this relay after membership maintenance or
revocation and distribute the new epoch to consumers. Outbox entries fence new
issuance until acknowledged. An offline consumer needs fresh epoch/revocation
metadata; cryptographic verification alone cannot recall a previously issued
credential. Already valid credentials remain bounded by their signed expiry.

Global suspension is separate: after authenticating cglb's signed public status,
the service calls `update_passport_policy`. This refuses epoch rollback and
serializes updates with local signing. Changed global metadata invalidates old
challenges; fresh challenges reject old-epoch passports. A suspended person
cannot get a replacement global passport, so community renewal fails closed.
The global service never needs a community membership list. Issuer key updates,
canonical routing, configuration freshness and device-key authorization remain
service responsibilities. Configuration expiry prevents new challenges/issuance;
it is not an independently fabricated gate-expiry assertion.

## Storage, concurrency and recovery

Use one physical database per community and one `crlt::Db`. Append
`cmbr::SCHEMAS` (including clbs), cgts, crbk, cplc, csgn and `storage::SCHEMA`
exactly once to the complete migration history; reuse that history on reopen.
cmty adds no tables. Memory and libSQL challenge stores delegate to cpsd.
Challenges contain anonymous nonce/binding/deadline only. Index plans, namespaces,
capacity, missing-schema failures and restart replay protection are tested.

Slow gate/provider checks execute outside the policy mutex. The current settings
are checked again before committing admission. cmbr serializes per member and
its source guard survives through signing. There is no extra community issuance
mutex or durable busy flag. cplc/csgn fences competing persistent signers.
Admission and signing are separate commits: a signing failure can leave a member
admitted, but returns no credential. Retry with a fresh presentation. Cancellation
cannot leave a cmbr writer permanently busy; unused anonymous challenges expire.

No credentials, presentations, raw gates, personal identifiers, profile values,
salts or request logs are persisted by cmty. Do not enable request/body tracing.
Errors are redacted. The public global API exposes signed aggregate policy
metadata, not global account records or uniqueness fingerprints.

## Verification and limits

Tests compose real BBS proofs, authenticated wallet requests, software WebAuthn,
cnrl enrolment, retained/transient gates, v2 pins, crbk decisions and Ed25519 COSE
through all three facades on libSQL. They cover replay/races, policy/schema/key
changes, wrong identity/context, legal veto, adaptive expiry, probation, lapse,
release, restart, revocation forwarding and global suspension blocking renewal.
Optional Turso checks skip without explicitly supplied disposable credentials.
GitHub Actions checks formatting, Clippy, tests and a single exact revision of
every Corbet dependency. Cargo runs only on CI.

cblc's punishment/change-token/record extensions are not yet proven. The actual
cgts and cmbr adapters therefore refuse those operations; they never change a
pin without a proven spent token. Positive extension/spend integration remains
blocked on the leaf proof work. This facade has no production test gate; cglb's
explicit development feature is absent from release builds and refused in
production mode. Test fixtures are compiled only into integration test binaries.

For a running service, `refresh_passport_policy` also replaces the authenticated
configuration deadline after the service verifies a fresh signed global status.
It rejects expired deadlines and epoch rollback, serializes with issuance and
invalidates challenges bound to the previous configuration. The service retains
durable public revision/epoch floors and authorizes issuer-key installation.

Credential assembly includes seals only for fields whose current change preset
is restricted. Loosening a field to Free does not prevent renewal; its previous
stored seal is retained for a later tightening and omitted from the Free-field
credential.

## Additional devices

`begin_additional_registration` and `finish_additional_registration` expose cmbr's
session-authorized, UV-required passkey enrolment for the same membership. cmbr
and ckyh own its identity, lifecycle and atomic revocation checks. The door binds
single-use state to its initiating session. A passkey ecosystem is a device;
there is no manual key approval or recovery identity. Removing one passkey keeps
access through the remaining keys; losing every key permanently releases the
membership under NO RETURN.
