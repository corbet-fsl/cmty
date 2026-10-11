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

Global suspension is separate: after authenticating cgbl's signed public status,
the service calls `update_passport_policy`. This refuses epoch rollback and
serializes updates with local signing. Changed global metadata invalidates old
challenges; fresh challenges reject old-epoch passports. A suspended person
cannot get a replacement global passport, so community renewal fails closed.
The global service never needs a community membership list. Issuer key updates,
canonical routing and configuration freshness remain service responsibilities.
cmbr supplies the current passkey-bound device keys under the membership lease;
cplc refuses requested keys outside that independently read set. Bind a key with
`Membership::authorize_device_key` after real passkey authentication, then drain
revocations before asking for issuance. Supplying `devices` in a credential
request cannot create that binding. Configuration expiry prevents new challenges/issuance;
it is not an independently fabricated gate-expiry assertion.

## Storage, concurrency and recovery

Use one physical database per community and one `crlt::Db`. Append
`cmbr::SCHEMAS` (including clbs), cgts, crbk, cplc, csgn and `storage::SCHEMA`
exactly once to the complete migration history; reuse that history on reopen.
Append `cmbr::DEVICE_KEYS_SCHEMA` after that complete historical sequence; never
insert it into an already deployed sequence or renumber prior migrations.
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
blocked on the leaf proof work. This facade has no production test gate; cgbl's
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


The optional accounting flow uses Policy's original signed v3 grant, requested
through `AccountAdmission`/`finish_account_with`. Ordinary admission returns no
account grant. The full authenticated PassportPolicy (epoch, original expiry,
length-prefixed sorted gate names) is hashed using its original
`cmty.passport-policy.v1` domain; no member-provided or descriptor-derived cohort
is substituted. Policy derives the grant's actual community epoch, authorized
device and Balance policy digest from the same retained admission inputs.
`account` revalidates current passkey, admitted member, selected device, exact
pseudonym, community epoch, complete cohort digest and each original expiry under
Policy/member leases. The original worker retains those leases through native
completion and caller cancellation. Missing service refuses, and an uncertain
native/storage effect requires original Status reconciliation. No global gate
facts, account payload history or alternate ledger are persisted by Community.


The privileged `publish_account_record` wrapper retains the same owned Policy
lease through the native worker reply, exact material publication and Beacon
refresh. It projects the configured catalogue key through the actual Policy owner,
checks the same settings/cohort/period/epoch after awaits, samples a live monotonic
host clock and checks exclusive original deadlines before exposure. The native
common object and material descriptor must agree. An error after a possibly
committed native epoch is reported as reconciliation; no new ledger, invented
descriptor, alternate signer or false success is substituted. This is not a member
HTTP operation. A native owner/material/epoch must actually exist before success.


Requested account-grant issuance reports reconciliation for any failure after
actual Membership admission succeeded (including handle/schema/pin/signing or
Balance/grant failure). The member commit is not rolled back and no grant bytes
escape. Ordinary credential issuance and pre-admit errors keep their original
behavior. Retrying uses the actual committed membership class; it never invents
a no-effect outcome or resets the original member/ledger.

`tune_account_waiting_period` is a trusted host operation on that same worker,
never a member request or serialized administrative command. It requires the
explicit expected tuning revision and operator-selected seconds. Community holds
the actual Policy guard across the native operation, then rechecks current
configuration and live exclusive deadlines before returning its durable revision.
Failures after a possibly committed tuning report reconciliation; the host must
observe the same ledger rather than recreate it. Positive tune/reload/reopen
qualification belongs to the actual native host journey.

The native host installs `with_native_account_service` and retains the exact
`account_shutdown` handle outside Community, Policy and member locks. It fences
host requests first, then awaits mandatory native cancellation and same-worker
join before closing CRLT's async runtime. Cancelled shutdown waiters cannot
abandon that join; late possibly committed operations require reconciliation.
The generic constructor remains an explicit drain-only path. Graceful drain
budgets do not promise hard operating-system cleanup timing.

`change_pin` selects a currently restricted schema field under the Policy guard,
retains Membership's exact pending change through the same native account worker,
and consumes its sealed completed-spend result under the original pin CAS. The
host supplies the real session's exclusive expiry and the same live observed
clock as Membership; the original receipt expiry cannot extend session authority.
Current Policy/passport bounds remain held through commit. The host must recheck
the exact session after return; a possibly committed late result is reconciled
by reading the existing pin, never by spending again.

## Mandatory root-board admission

The reserved `root` community requires `Community::new_root_board`. Its retained
challenge contains the original CPSD joint root request and its current signed
common descriptor. Ordinary passport verification refuses this mode before
consuming the challenge. The actual joint verifier consumes the original nonce,
proves the same hidden holder, and caps global evidence by both cohort lifetimes.
Registration and the unchanged membership/gate/credential pipeline recheck the
current descriptor and complete Policy snapshot. Root membership grants no
operator role and discloses no source community or role. Source-role authorization
and root-credential issuance remain separate service responsibilities.

The original in-process source-role path uses `root_board_issuer` on the actual
root Community. This opaque owner retains its dedicated provisioned CPSD key,
the same root nonce store and the same Policy mutex; source configuration never
receives the key. Source communities call `begin_root_board_issuance` and
`finish_root_board_issuance` using genuine garden passkey authentication, the
original guarded session expiry and the direct shared live clock. Root Policy
is locked before source Policy, then the actual Membership role lease. Root
cannot be its own source and aliased Policy owners are refused before locking.

The two original signed requests bind the complete common descriptor and global
cohort. The inclusive proof deadline is strictly below every exclusive session,
membership, authenticated settings, global policy and publication bound. The
source verifier uses its installed complete global ring; no request selects it.
The verified source pseudonym must match the actual current Admin/Root lease.

After the root nonce is consumed, Membership takes its actual source database's
Immediate writer barrier and rechecks key, role, lifecycle and legal standing
through their owners. It uses the original second pooled read connection;
insufficient pool capacity refuses. Original CPSD signing runs synchronously
inside that barrier, with strict live-time cuts and acknowledged read-only
cleanup before returning the answer. Acquiring the barrier after nonce
consumption also supports root/source scopes sharing one physical database.
Cancellation, expiry or unknown cleanup withholds the answer and never restores
the consumed nonce. No source identity, role history or response cache is added
to root storage. The host retains its actual session owner through synchronous
response publication; a copied expiry alone is not session authority.

Native member accounting requires the exact authenticated key and a retained
`AccountSession` supplied by the actual host session owner. Community retains
its Policy lock and opaque Membership source lease through the original native
worker. At the same database's existing writer-held commit decision it checks
current read-only Policy state, passkey/member/device facts, both membership and
account legal actions, and the original session/grant/cohort lifetimes. All final
owner reads remain in the native clock's sampled second. Session invalidation
must survive request cancellation and must not reacquire the outer Community
lock. The host keeps the asynchronous runtime and database alive until native
workers join. Status uses this boundary too; it does not qualify a ZK proof.
