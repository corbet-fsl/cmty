use chrono::{DateTime, Datelike};

mod accounting;
pub use accounting::{AccountAdmission, AccountPublication, AccountSession, PinChange};
mod certificate;
mod root_board;
mod root_issuance;
pub use certificate::PasskeyCertificate;
use cpsd::{
    ChallengeStore, CommunityId, IssuerPublicKey, Presentation, PresentationRequest, Verifier,
    rand::{CryptoRng, RngCore},
};
pub use root_issuance::{RootBoardChallenge, RootBoardIssuer, RootBoardSession};
use tokio::sync::Mutex;

use crate::{storage::Storage, *};

/// Server-held admission challenge. Only the request travels to the holder.
pub struct Challenge {
    request: PresentationRequest,
    root_board: Option<cpsd::RootBoardRequest>,
    signed_request: Vec<u8>,
    policy: PolicySnapshot,
    not_before: u64,
}

impl Challenge {
    /// Authenticated COSE request for the wallet; it verifies its selected origin.
    pub fn signed_request(&self) -> &[u8] {
        &self.signed_request
    }

    /// Serializable passport request; retain this handle on the server.
    pub fn request(&self) -> &PresentationRequest {
        &self.request
    }
    /// Mandatory joint proof request, only for the admin board (selected by the host, not by name).
    pub fn root_board_request(&self) -> Option<&cpsd::RootBoardRequest> {
        self.root_board.as_ref()
    }
}

/// A consumed, verified passport presentation. No raw proof is retained.
/// Use it immediately to bind a first registration to its community pseudonym.
///
/// ```compile_fail
/// let raw: cpsd::Pseudonym = todo!();
/// let verified: cmty::VerifiedPassport = raw.into();
/// ```
pub struct VerifiedPassport {
    member_id: String,
    witness: cgts::VerifiedPassport,
    community: CommunityId,
    policy: PolicySnapshot,
    verified_at: u64,
    root_board: Option<cpsd::RootBoardPublicKey>,
}

impl VerifiedPassport {
    /// Verified canonical community pseudonym, also the cmbr member ID.
    pub fn member_id(&self) -> &str {
        &self.member_id
    }
}

/// Authenticated service configuration, never taken from the holder's request.
#[derive(Clone)]
pub struct Config {
    /// Global common-expiry epoch, authenticated from the global issuer.
    pub passport: PassportPolicy,
    /// Exclusive freshness deadline for community configuration.
    pub valid_until: u64,
    /// Positive single-use challenge lifetime, at most five minutes.
    pub challenge_lifetime: u64,
}

/// The three real facades, each retaining its own responsibility.
/// All stores must use one physical community database and the same action.
pub struct Parts<M, L, C, G, A, R, P, K> {
    /// Owns passkeys, enrolment, handles, pins, leases, lapse and release.
    pub membership: cmbr::Membership<M, L, C>,
    /// Owns gate execution, retained facts and the mandatory legal veto.
    pub gates: cgts::Gatekeeper<G, A>,
    /// Owns policy decisions, schema, credential format, lifetimes and signing.
    pub policy: cplc::Policy<R, P, K>,
}

/// Inputs from an authenticated service session. cmbr validates the passkey
/// authentication and its pseudonym binding. The service authorizes device keys.
/// cmbr owns standing. Never deserialize this input.
pub struct Admission<'a> {
    /// A committed ckyh login for the enrolled community-local user.
    pub authentication: &'a ckyh::Authentication,
    /// Public device keys authorized by the service's device protocol.
    pub devices: &'a [[u8; 32]],
    /// Coarse lease end from the service's retention policy, not credential expiry.
    pub lease: crgs::YearMonth,
    /// Exact originating host session; removal or replacement invalidates it.
    pub session: &'a dyn cmbr::RoleSession,
    /// Creation id of a community being created, for its creator's first-admin
    /// admission only. Membership checks it against the recorded commitment.
    pub creation: Option<&'a str>,
}

/// Community composition over cmbr, cgts and cplc. There is no local member
/// store, gate engine, policy evaluator, lifetime calculator or signer.
pub struct Community<S: Storage, M, L, C, G, A, R, P, K> {
    community: CommunityId,
    root_board: bool,
    verifier: Verifier<S::Challenges>,
    root_issuance_store: S::Challenges,
    membership: cmbr::Membership<M, L, C>,
    gates: cgts::Gatekeeper<G, A>,
    policy: std::sync::Arc<Mutex<cplc::Policy<R, P, K>>>,
    config: std::sync::RwLock<Config>,
}

impl<S, M, L, C, G, A, R, P, K> Community<S, M, L, C, G, A, R, P, K>
where
    S: Storage,
    M: cmbr::Storage + Send + Sync + 'static,
    L: clbs::Verifier + Send + Sync + 'static,
    C: clbs::Clock + Send + Sync + 'static,
    G: cgts::Storage,
    A: cgts::LegalVeto,
    R: crbk::Storage,
    P: cplc::Storage,
    K: csgn::Store,
{
    /// Compose actual community facades. Configure cmbr/cplc with
    /// [`ADMISSION_ACTION`], and share the rulebook via `SharedRulebook`.
    /// Global issuer keys and the common epoch schedule must be authenticated.
    pub fn new(
        storage: S,
        issuer_keys: Vec<IssuerPublicKey>,
        parts: Parts<M, L, C, G, A, R, P, K>,
        config: Config,
    ) -> Result<Self> {
        Self::new_selected(storage, issuer_keys, parts, config, false)
    }

    fn new_selected(
        storage: S,
        issuer_keys: Vec<IssuerPublicKey>,
        parts: Parts<M, L, C, G, A, R, P, K>,
        config: Config,
        root_board: bool,
    ) -> Result<Self> {
        let store = storage.challenges();
        let community = store.community().clone();
        let name = community_text(&community)?;
        // The admin board is selected by the host's constructor (public descriptor present), never by
        // the community name: a community called "root" is an ordinary community.
        if parts.policy.key_ring().map_err(policy_error)?.issuer() != name
            || parts.membership.community() != name
            || parts.gates.community() != name
        {
            return Err(Error::Scope);
        }
        if config.challenge_lifetime == 0 || config.challenge_lifetime > 300 {
            return Err(Error::Time);
        }
        if issuer_keys.is_empty() {
            return Err(Error::Passport);
        }
        if config.passport.gates.is_empty() || !config.passport.valid_until.is_multiple_of(86_400) {
            return Err(Error::Policy);
        }
        Ok(Self {
            community,
            root_board,
            verifier: Verifier::new(store, issuer_keys)?,
            root_issuance_store: storage.challenges(),
            membership: parts.membership,
            gates: parts.gates,
            policy: std::sync::Arc::new(Mutex::new(parts.policy)),
            config: std::sync::RwLock::new(config),
        })
    }

    /// Canonical community identity for pseudonym derivation.
    pub fn community(&self) -> &CommunityId {
        &self.community
    }

    /// Membership owns per-person serialization and the revocation outbox.
    pub fn membership(&self) -> &cmbr::Membership<M, L, C> {
        &self.membership
    }

    /// Gate execution, headless steps and provider withdrawal remain with cgts.
    pub fn gates(&self) -> &cgts::Gatekeeper<G, A> {
        &self.gates
    }

    /// Serialize policy administration with signing. Slow gate checks run outside
    /// this mutex; cplc fences competing persistent signer instances.
    pub fn policy(&self) -> &Mutex<cplc::Policy<R, P, K>> {
        &self.policy
    }

    /// Load current effective policy and authenticated public signing metadata.
    pub async fn snapshot(&self, now: u64) -> Result<PolicySnapshot> {
        check_time(now)?;
        self.snapshot_locked(&*self.policy.lock().await, now).await
    }

    /// Reserve a single-use passport request. Rate-limit before this operation.
    pub async fn begin<T: RngCore + CryptoRng>(&self, rng: &mut T, now: u64) -> Result<Challenge> {
        self.begin_selected(rng, now).await
    }

    /// Verify and atomically consume a presentation before any membership work.
    /// Replays, foreign scopes and changed policy fail closed.
    pub async fn verify<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        now: u64,
    ) -> Result<VerifiedPassport> {
        check_time(now)?;
        if self.root_board
            || challenge.root_board.is_some()
            || now < challenge.not_before
            || challenge.request.community() != &self.community
        {
            return Err(Error::Passport);
        }
        let policy = self.snapshot(now).await?;
        if !policy.unchanged(&challenge.policy) {
            return Err(Error::Policy);
        }
        let witness = cgts::verify_passport(
            &self.verifier,
            rng,
            &challenge.request,
            presentation,
            policy.passport.epoch,
            now,
        )
        .await
        .map_err(|_| Error::Passport)?;
        Ok(VerifiedPassport {
            member_id: witness.pseudonym().to_hex(),
            witness,
            community: self.community.clone(),
            policy,
            verified_at: now,
            root_board: None,
        })
    }

    /// Consume a freshly verified passport and let cmbr start the passkey ceremony.
    /// The UUID is service-generated and community-local. Resume later through
    /// cmbr; final admission requires a new passport presentation and real login.
    pub async fn begin_registration(
        &self,
        passport: VerifiedPassport,
        user: ckyh::Uuid,
        now: u64,
    ) -> Result<(ckyh::CreationChallengeResponse, cmbr::PendingRegistration)> {
        self.begin_registration_for(passport, user, None, now).await
    }

    /// Bind the original creation reference to this fresh first registration.
    /// The seed is public provenance, not a holder secret or member authority.
    pub async fn begin_initial_registration(
        &self,
        passport: VerifiedPassport,
        user: ckyh::Uuid,
        seed: [u8; 32],
        now: u64,
    ) -> Result<(ckyh::CreationChallengeResponse, cmbr::PendingRegistration)> {
        self.begin_registration_for(passport, user, Some(seed), now)
            .await
    }

    async fn begin_registration_for(
        &self,
        passport: VerifiedPassport,
        user: ckyh::Uuid,
        seed: Option<[u8; 32]>,
        now: u64,
    ) -> Result<(ckyh::CreationChallengeResponse, cmbr::PendingRegistration)> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        let policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        match seed {
            Some(seed) => {
                self.membership
                    .begin_initial_registration(user, &passport.member_id, seed)
                    .await
            }
            None => {
                self.membership
                    .begin_registration(user, &passport.member_id)
                    .await
            }
        }
        .map_err(member_error)
    }

    /// JOIN by device key (one-confirmation model). The host has verified one confirmation
    /// stamp for this exact key and `seed` under the passport's pseudonym; this checks the
    /// passport like a registration does and binds `device_key` as the member's first ACTIVE
    /// key holding `seed`, the opaque initial creation commitment. A retry with the same key
    /// and seed returns the same member.
    pub async fn join_with_device_key(
        &self,
        passport: VerifiedPassport,
        user: ckyh::Uuid,
        device_key: [u8; 32],
        seed: [u8; 32],
        now: u64,
    ) -> Result<cmbr::Record> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        let policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        self.membership
            .join_with_device_key(user, &passport.member_id, device_key, seed)
            .await
            .map_err(member_error)
    }

    /// The already applied JOIN by device key of the passport's pseudonym: exactly this key
    /// holding exactly `seed`, still ACTIVE. Read only. The host answers a retried join with it
    /// when the join's stamp no longer verifies (its cohort ended), after the same passport
    /// check a join makes; `None` when this join was never applied (a new stamp is needed).
    pub async fn device_join_applied(
        &self,
        passport: VerifiedPassport,
        device_key: [u8; 32],
        seed: [u8; 32],
        now: u64,
    ) -> Result<Option<cmbr::Record>> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        let policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        self.membership
            .device_join_applied(&passport.member_id, device_key, seed)
            .await
            .map_err(member_error)
    }

    /// Stamped pairing, step one: the host verified a confirmation stamp covering exactly
    /// `device_key` under the passport's pseudonym. Registers the key PENDING (grants nothing).
    /// An equal retry succeeds.
    pub async fn add_device_key(
        &self,
        passport: VerifiedPassport,
        device_key: [u8; 32],
        now: u64,
    ) -> Result<()> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        let policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        self.membership
            .add_device_key(&passport.member_id, device_key)
            .await
            .map_err(member_error)
    }

    /// Stamped pairing, step two: the host verified the activation stamp. Makes the PENDING
    /// key ACTIVE; idempotent for an already active key.
    pub async fn activate_device_key(
        &self,
        passport: VerifiedPassport,
        device_key: [u8; 32],
        now: u64,
    ) -> Result<()> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        let policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        self.membership
            .activate_device_key(&passport.member_id, device_key)
            .await
            .map_err(member_error)
    }

    /// Begin another passkey for the authenticated membership, without approval.
    /// The door owns session lifetime and keeps the pending state in that session.
    pub async fn begin_additional_registration(
        &self,
        authentication: &ckyh::Authentication,
    ) -> Result<(
        ckyh::CreationChallengeResponse,
        cmbr::PendingAdditionalRegistration,
    )> {
        self.membership
            .begin_additional_registration(authentication)
            .await
            .map_err(member_error)
    }

    /// Complete the same membership's UV-required additional-passkey ceremony.
    pub async fn finish_additional_registration(
        &self,
        authentication: &ckyh::Authentication,
        state: cmbr::PendingAdditionalRegistration,
        response: ckyh::RegisterPublicKeyCredential,
    ) -> Result<ckyh::StoredPasskey> {
        self.membership
            .finish_additional_registration(authentication, state, response)
            .await
            .map_err(member_error)
    }

    /// Verify a fresh passport, collect cgts facts, decide through cplc, commit
    /// cmbr admission and issue cplc's Ed25519 COSE credential through csgn.
    pub async fn finish<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        admission: Admission<'_>,
        now: u64,
    ) -> Result<Outcome> {
        self.finish_with(
            rng,
            challenge,
            presentation,
            admission,
            now,
            async |_, _| Ok(Vec::new()),
        )
        .await
    }

    /// Also run transient/action-bound gates through the supplied real cgts
    /// instance. cgts checks each receipt's subject, action, revision and time.
    /// Raw leaf inputs stay in this server callback, never in cmty storage.
    pub async fn finish_with<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        admission: Admission<'_>,
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        self.finish_selected(rng, challenge, presentation, (admission, None), now, checks)
            .await
    }

    async fn finish_selected<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        selection: (Admission<'_>, Option<[u8; 32]>),
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        let passport = self.verify(rng, challenge, presentation, now).await?;
        self.finish_verified(passport, selection, now, checks).await
    }

    async fn finish_verified(
        &self,
        passport: VerifiedPassport,
        selection: (Admission<'_>, Option<[u8; 32]>),
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        self.finish_verified_entitled(passport, selection, now, checks)
            .await
    }

    async fn finish_verified_entitled(
        &self,
        passport: VerifiedPassport,
        selection: (Admission<'_>, Option<[u8; 32]>),
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        let (admission, account_device) = selection;
        let snapshot = {
            let mut policy = self.policy.lock().await;
            self.passport_current(&passport, &policy, now).await?;
            policy.verified_settings(now).await.map_err(policy_error)?
        };
        let auth = admission.authentication;
        let row = match self.membership.resume(auth).await {
            Ok(row) => row,
            Err(cmbr::Error::Restricted) => return Ok(Outcome::Vetoed),
            Err(error) => return Err(member_error(error)),
        };
        if !scope_subject_matches(
            row.community(),
            community_text(&self.community)?,
            row.subject(),
            &passport.member_id,
        ) {
            return Err(Error::Membership);
        }
        let subject = crbk::Subject {
            id: row.subject(),
            membership: row.state().membership(),
        };
        let context = cgts::Context {
            snapshot: snapshot.settings(),
            subject: row.subject(),
            action: ADMISSION_ACTION,
            now: now as i64,
        };
        let checked = match checks(&self.gates, context).await {
            Ok(checked) => checked,
            Err(cgts::Error::Vetoed) => return Ok(Outcome::Vetoed),
            Err(_) => return Err(Error::Gate),
        };
        let mut checked = checked;
        // The recorded creator's verified passport stands in for the new
        // community's voucher step (L1352); first-admin admission still matches
        // the exact creation commitment under its own writer.
        if admission.creation.is_some()
            && let Some(founding) = cgts::gates::FoundingVoucher::for_snapshot(context.snapshot)
            && self
                .membership
                .is_recorded_creator(auth)
                .await
                .map_err(member_error)?
        {
            match self.gates.run(context, &founding, &passport.witness).await {
                Ok(gate) => checked.push(gate),
                Err(cgts::Error::Vetoed) => return Ok(Outcome::Vetoed),
                Err(_) => return Err(Error::Gate),
            }
        }
        checked.extend(passport.witness.gates(context).map_err(|_| Error::Gate)?);
        let checked = match self.gates.check(context, checked).await {
            Ok(checked) => checked,
            Err(cgts::Error::Vetoed) => return Ok(Outcome::Vetoed),
            Err(_) => return Err(Error::Gate),
        };
        let mut policy = self.policy.lock().await;
        self.passport_current(&passport, &policy, now).await?;
        policy
            .validate_snapshot(&snapshot, now)
            .await
            .map_err(policy_error)?;
        let decision = policy
            .may(&snapshot, subject, ADMISSION_ACTION, &checked, now)
            .await
            .map_err(policy_error)?;
        // Device authorization is checked before any admission commit: a refusal
        // here changes nothing, while the same failure after the commit would only
        // be reportable as uncertainty.
        let authorized = self
            .membership
            .current_device_keys(auth)
            .await
            .map_err(member_error)?;
        if admission.devices.is_empty()
            || admission
                .devices
                .iter()
                .any(|key| !authorized.contains(key))
        {
            return Err(Error::Membership);
        }
        let request = cmbr::AdmissionRequest {
            authentication: auth,
            policy: &policy,
            snapshot: &snapshot,
            gates: &checked,
            checked_at: now,
            lease: admission.lease,
            session: admission.session,
        };
        if !decision.allowed {
            // This explicit admission attempt may lapse an admitted row. Merely
            // rendering the cmbr lobby never performs this transition.
            self.membership
                .lapse_current(request)
                .await
                .map_err(|error| match error {
                    cmbr::Error::Unavailable => Error::Reconcile,
                    error => member_error(error),
                })?;
            return Ok(Outcome::Missing(decision));
        }
        let admitted = match admission.creation {
            // The board's first seat is the Root seat of the platform role; every other community's
            // creator is its first admin. `root_board` comes from the host's constructor.
            Some(id) if self.root_board => self.membership.admit_first_root(request, id).await,
            Some(id) => self.membership.admit_first_admin(request, id).await,
            None => self.membership.admit_current(request).await,
        }
        .map_err(|error| match error {
            cmbr::Error::Unavailable => Error::Reconcile,
            error => member_error(error),
        })?;
        // Credential/account issuance may fail after this real membership
        // commit. Withhold the result without implying admission rollback.
        let result: Result<Outcome> = async {
            let handle = self
                .membership
                .handle(auth)
                .await
                .map_err(member_error)?
                .ok_or(Error::Membership)?;
            let schema = policy
                .schema()
                .map_err(policy_error)?
                .ok_or(Error::Policy)?;
            let schema_version = schema.version;
            let mut pins = Vec::new();
            for field in schema.public.iter().chain(&schema.private) {
                if field.change_preset == cplc::cshm::ChangePreset::Free {
                    continue;
                }
                if let Some(pin) = self
                    .membership
                    .get_pin(auth, &field.id)
                    .await
                    .map_err(member_error)?
                {
                    pins.push(cplc::Pin {
                        field: field.id.clone(),
                        fingerprint: *pin.fingerprint.as_bytes(),
                    });
                }
            }
            self.passport_current(&passport, &policy, now).await?;
            // A cmbr commit can precede a signing failure. No bytes escape on failure;
            // retries start with a new presentation and do not change member class.
            let request = || cplc::CredentialRequest {
                subject: crbk::Subject {
                    id: admitted.subject(),
                    membership: admitted.state().membership(),
                },
                handle: handle.display(),
                schema_version,
                snapshot: &snapshot,
                gates: &checked,
                pins: &pins,
                devices: admission.devices,
            };
            let cose = policy
                .issue(&self.membership, request(), now)
                .await
                .map_err(issuance_error)?;
            let verified = policy
                .key_ring()
                .map_err(signing_error)?
                .verify(&cose, csgn::Kind::Credential, now)
                .map_err(signing_error)?;
            let payload: cplc::Credential =
                serde_json::from_slice(verified.payload()).map_err(signing_error)?;
            let claims = CredentialClaims {
                version: 1,
                purpose: payload.purpose,
                issuance_action: payload.issuance_action,
                community: payload.community,
                member_id: payload.member,
                handle: payload.handle,
                gates: payload
                    .gates
                    .into_iter()
                    .map(|gate| CredentialGate {
                        gate: gate.gate,
                        provider: gate.provider,
                        valid_until: gate.valid_until,
                    })
                    .collect(),
                pins: payload
                    .pins
                    .into_iter()
                    .map(|pin| (pin.field, pin.fingerprint))
                    .collect(),
                devices: payload.devices,
                schema_version: payload.schema_version.into(),
                policy_epoch: payload.policy_epoch,
                issued: verified.issued_at(),
                valid_until: verified.valid_until(),
                key_id: verified.key_id().as_bytes().to_vec(),
            };
            let account = match account_device {
                Some(device) => Some(
                    policy
                        .issue_account_grant(
                            &self.membership,
                            request(),
                            device,
                            cplc::AccountGrantContext {
                                passport_policy_digest: passport.policy.passport.digest(),
                                passport_valid_until: passport
                                    .policy
                                    .passport
                                    .valid_until
                                    .min(passport.policy.valid_until),
                            },
                            now,
                        )
                        .await
                        .map_err(issuance_error)?,
                ),
                None => None,
            };
            Ok(Outcome::Issued(Box::new(IssuedCredential {
                claims,
                cose,
                account,
            })))
        }
        .await;
        // The original membership admission is already committed, including
        // ordinary issuance. Later failure never implies that it rolled back.
        result.map_err(|_| Error::Reconcile)
    }

    /// Retain revoked passkey IDs and publish a conservative community epoch
    /// advance before acknowledging each membership event. A crash may repeat
    /// the advance, never lose revocation or remove an existing revoked ID.
    /// Call after passkey revocation/maintenance; `begin` also drains this outbox.
    pub async fn flush_revocations(&self, now: u64) -> Result<usize> {
        check_time(now)?;
        let mut policy = self.policy.lock().await;
        let events = self
            .membership
            .revocations(256)
            .await
            .map_err(member_error)?;
        if !events.is_empty() {
            let mut revocations = policy.revocations().map_err(policy_error)?.clone();
            for event in &events {
                revocations.passkeys.extend(
                    self.membership
                        .revoked_passkeys(event)
                        .await
                        .map_err(member_error)?,
                );
            }
            policy
                .set_revocations(revocations)
                .await
                .map_err(policy_error)?;
            policy
                .publish(cplc::SnapshotKind::Settings, now)
                .await
                .map_err(policy_error)?;
            policy
                .publish(cplc::SnapshotKind::RevocationList, now)
                .await
                .map_err(policy_error)?;
            for event in &events {
                self.membership
                    .acknowledge_revocation(event)
                    .await
                    .map_err(member_error)?;
            }
        }
        Ok(events.len())
    }

    /// Install authenticated global policy metadata after checking cgbl's signed
    /// public status. Never source this from a holder. Epoch rollback is refused;
    /// the signing mutex excludes an update halfway through local issuance.
    pub async fn update_passport_policy(&self, passport: PassportPolicy) -> Result<()> {
        let _policy = self.policy.lock().await;
        let mut config = self.config.write().map_err(policy_error)?;
        if passport.epoch < config.passport.epoch
            || passport.gates.is_empty()
            || !passport.valid_until.is_multiple_of(86_400)
            || passport.valid_until >= cpsd::TIME_LIMIT
        {
            return Err(Error::Policy);
        }
        config.passport = passport;
        Ok(())
    }

    /// Refresh authenticated global metadata and its transport freshness deadline.
    /// The service verifies the signed status and durable revision/epoch floors
    /// before this call. Existing challenges bind to the old configuration and
    /// are invalidated when it changes. Issuer-key installation remains explicit.
    pub async fn refresh_passport_policy(
        &self,
        passport: PassportPolicy,
        valid_until: u64,
        now: u64,
    ) -> Result<()> {
        check_time(now)?;
        if valid_until <= now
            || valid_until >= cpsd::TIME_LIMIT
            || passport.valid_until <= now
            || passport.valid_until >= cpsd::TIME_LIMIT
            || !passport.valid_until.is_multiple_of(86_400)
            || passport.gates.is_empty()
        {
            return Err(Error::Policy);
        }
        let _policy = self.policy.lock().await;
        let mut config = self.config.write().map_err(policy_error)?;
        if passport.epoch < config.passport.epoch {
            return Err(Error::Policy);
        }
        config.passport = passport;
        config.valid_until = valid_until;
        Ok(())
    }

    /// Delete expired anonymous outstanding challenges.
    pub async fn prune(&self, now: u64) -> Result<u64> {
        check_time(now)?;
        Ok(self.verifier.prune(now).await?)
    }

    async fn snapshot_locked(
        &self,
        policy: &cplc::Policy<R, P, K>,
        now: u64,
    ) -> Result<PolicySnapshot> {
        check_time(now)?;
        let rules = policy.settings(now).await.map_err(policy_error)?;
        let config = self.config.read().map_err(policy_error)?.clone();
        let snapshot = PolicySnapshot {
            rules,
            schema_version: policy
                .schema()
                .map_err(policy_error)?
                .ok_or(Error::Policy)?
                .version
                .into(),
            passport: config.passport,
            valid_until: config.valid_until,
            signing_keys: policy.key_ring().map_err(policy_error)?.clone(),
        };
        if snapshot.passport.valid_until <= now
            || snapshot.passport.valid_until >= cpsd::TIME_LIMIT
            || snapshot.valid_until <= now
            || snapshot.valid_until >= cpsd::TIME_LIMIT
        {
            return Err(Error::Policy);
        }
        Ok(snapshot)
    }
}

fn member_error(error: cmbr::Error) -> Error {
    match error {
        cmbr::Error::Identity => Error::Scope,
        _ => Error::Membership,
    }
}

/// Shared redaction for policy-unavailable call sites.
fn policy_error<E>(_: E) -> Error {
    Error::Policy
}

/// Shared redaction for signing-failure call sites.
fn signing_error<E>(_: E) -> Error {
    Error::Signing
}

/// Redaction for credential issuance: denials and revocations are policy
/// refusals, every other issuance failure is a signing failure.
fn issuance_error(error: cplc::Error) -> Error {
    match error {
        cplc::Error::Denied(_) | cplc::Error::Revoked => Error::Policy,
        _ => Error::Signing,
    }
}

/// Scope and subject isolation check: both the community scope and the member
/// subject must match.
fn scope_subject_matches(
    actual_community: &str,
    expected_community: &str,
    actual_subject: &str,
    expected_subject: &str,
) -> bool {
    actual_community == expected_community && actual_subject == expected_subject
}

/// Shared policy-freshness guard used at each issuance checkpoint.
fn ensure_unchanged(expected: &PolicySnapshot, current: &PolicySnapshot) -> Result<()> {
    if !expected.unchanged(current) {
        return Err(Error::Policy);
    }
    Ok(())
}

fn check_time(now: u64) -> Result<()> {
    if now == 0
        || now >= cpsd::TIME_LIMIT
        || DateTime::from_timestamp(now as i64, 0).is_none_or(|date| date.year() > 9999)
    {
        return Err(Error::Time);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpsd::rand::{SeedableRng, rngs::StdRng};
    use cpsd::{
        AuthenticatedIssuance, GateId, HolderSecret, IssuerKey, KeyId, Passport,
        PassportAttributes, issuance_challenge, issue_blind_once, request_issue,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::{Arc, atomic::AtomicI64};

    const NOW: u64 = 1_800_000_000 / 86_400 * 86_400;
    const EXPIRY: u64 = NOW + 90 * 86_400;
    const ORIGIN: &str = "https://members.example.org";

    #[test]
    fn member_error_maps_identity_to_scope() {
        assert_eq!(member_error(cmbr::Error::Identity), Error::Scope);
        assert_eq!(member_error(cmbr::Error::Transition), Error::Membership);
    }

    #[test]
    fn issuance_error_maps_denials_and_revocation_to_policy() {
        let denied = cplc::Error::Denied(crbk::Decision {
            allowed: false,
            missing: Vec::new(),
        });
        assert_eq!(issuance_error(denied), Error::Policy);
        assert_eq!(issuance_error(cplc::Error::Revoked), Error::Policy);
    }

    #[test]
    fn issuance_error_maps_all_other_failures_to_signing() {
        assert_eq!(issuance_error(cplc::Error::Signing), Error::Signing);
        assert_eq!(issuance_error(cplc::Error::Storage), Error::Signing);
        assert_eq!(issuance_error(cplc::Error::Verification), Error::Signing);
        assert_eq!(issuance_error(cplc::Error::Conflict), Error::Signing);
    }

    #[test]
    fn scope_subject_matches_checks_both_identifiers() {
        assert!(scope_subject_matches(
            "example", "example", "member-a", "member-a"
        ));
        assert!(!scope_subject_matches(
            "foreign", "example", "member-a", "member-a"
        ));
        assert!(!scope_subject_matches(
            "example", "example", "member-a", "member-b"
        ));
        assert!(!scope_subject_matches(
            "foreign", "example", "member-a", "member-b"
        ));
    }

    #[test]
    fn check_time_accepts_now() {
        assert!(check_time(1_800_000_000).is_ok());
    }

    #[test]
    fn check_time_rejects_zero_and_limit() {
        assert_eq!(check_time(0), Err(Error::Time));
        assert_eq!(check_time(cpsd::TIME_LIMIT), Err(Error::Time));
    }

    #[test]
    fn check_time_rejects_year_beyond_9999() {
        // 300B is below TIME_LIMIT (1<<40) but its calendar year exceeds 9999.
        assert_eq!(check_time(300_000_000_000), Err(Error::Time));
    }

    /// Real signature verification at the external authority boundary.
    #[derive(Clone)]
    struct Authority;

    impl clbs::Verifier for Authority {
        async fn verify_legal(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
            let signature = ed25519_dalek::Signature::from_slice(&order.proof)
                .map_err(|_| clbs::Error::Denied)?;
            SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .verify_strict(&order.order.signing_payload()?, &signature)
                .map_err(|_| clbs::Error::Denied)
        }

        async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
            Err(clbs::Error::Denied)
        }
    }

    #[derive(Clone)]
    struct Clock(Arc<AtomicI64>);

    impl clbs::Clock for Clock {
        fn now(&self) -> clbs::Result<i64> {
            Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    fn legal_order() -> clbs::SignedOrder {
        let order = clbs::Order {
            community: "example".into(),
            id: "legal-test".into(),
            subject: "member".into(),
            reference: "synthetic-authority".into(),
            entered_by: "authority".into(),
            kind: clbs::OrderKind::Legal {
                authority: "test-authority".into(),
            },
            scope: clbs::Scope::Member,
        };
        let proof = SigningKey::from_bytes(&[7; 32])
            .sign(&order.signing_payload().unwrap())
            .to_bytes()
            .to_vec();
        clbs::SignedOrder { order, proof }
    }

    #[test]
    fn authority_clock_reports_configured_time() {
        let clock = Clock(Arc::new(AtomicI64::new(42)));
        assert_eq!(clbs::Clock::now(&clock).unwrap(), 42);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authority_accepts_valid_and_rejects_tampered_orders() {
        let authority = Authority;
        let valid = legal_order();
        assert!(
            clbs::Verifier::verify_legal(&authority, &valid)
                .await
                .is_ok()
        );
        let mut tampered = legal_order();
        tampered.proof[63] ^= 1;
        assert!(matches!(
            clbs::Verifier::verify_legal(&authority, &tampered).await,
            Err(clbs::Error::Denied)
        ));
        let malformed = clbs::SignedOrder {
            order: legal_order().order,
            proof: vec![0; 8],
        };
        assert!(matches!(
            clbs::Verifier::verify_legal(&authority, &malformed).await,
            Err(clbs::Error::Denied)
        ));
        assert!(matches!(
            clbs::Verifier::verify_self_ban(&authority, &valid).await,
            Err(clbs::Error::Denied)
        ));
    }

    type TestEngine = Community<
        crate::storage::MemoryStorage,
        cmbr::LibsqlStorage,
        Authority,
        Clock,
        cgts::LibsqlStore,
        cgts::LegalGate<cgts::legal_storage::LibsqlStore, Authority>,
        crate::adapters::SharedRulebook<crbk::LibsqlStore>,
        cplc::LibsqlStore,
        csgn::LibsqlStore,
    >;

    async fn test_db(directory: &tempfile::TempDir) -> crlt::Db {
        let db = crlt::Db::open(crlt::Config::new(
            format!("file://{}", directory.path().join("unit.db").display()),
            "",
        ))
        .await
        .unwrap();
        let mut schemas = cmbr::SCHEMAS.to_vec();
        schemas.extend([
            ("cgts", cgts::SCHEMA),
            ("crbk", crbk::SCHEMA),
            ("cplc", cplc::SCHEMA),
            ("csgn", csgn::SCHEMA),
            ("cpsd", crate::storage::SCHEMA),
            ("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA),
            ("cmbr-device-registry", cmbr::DEVICE_REGISTRY_SCHEMA),
            ("cmbr-device-pairing", cmbr::DEVICE_PAIRING_SCHEMA),
        ]);
        let migrations: Vec<_> = schemas
            .iter()
            .enumerate()
            .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
            .collect();
        db.migrate(&migrations).await.unwrap();
        assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
        db
    }

    fn test_rulebook() -> crbk::Rulebook {
        let mut rules = crbk::Rulebook::default();
        for (level, name, provider) in [
            (crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
            (crbk::GateLevel::Community, "dev-test", "test-only"),
        ] {
            for key in [
                crbk::gate_key(level, name),
                crbk::provider_key(level, name, provider),
            ] {
                rules
                    .define(
                        key,
                        crbk::Setting {
                            value_type: crbk::SettingType::Boolean,
                            nullable: false,
                            default: true.into(),
                            bounds: crbk::Bounds::default(),
                            lowest_layer: crbk::Layer::Community,
                            kind: crbk::SettingKind::Technical,
                        },
                    )
                    .unwrap();
            }
        }
        rules
            .define(
                crbk::action_key(ADMISSION_ACTION),
                crbk::Setting {
                    value_type: crbk::SettingType::Policy,
                    nullable: true,
                    default: serde_json::to_value(crbk::ActionPolicy {
                        all_of: vec![
                            crbk::Requirement {
                                gate: "global-test".into(),
                                level: crbk::GateLevel::Global,
                                provider: None,
                            },
                            crbk::Requirement {
                                gate: "dev-test".into(),
                                level: crbk::GateLevel::Community,
                                provider: None,
                            },
                        ],
                        ..Default::default()
                    })
                    .unwrap(),
                    bounds: crbk::Bounds::default(),
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
        rules
    }

    fn test_schema() -> cplc::cshm::Schema {
        serde_json::from_value(serde_json::json!({ "community":"example", "version":3,
            "public":[{"id":"restricted-field","label":"Restricted field", "kind":{"type":"yes_no"},
            "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}], "private":[] })).unwrap()
    }

    fn test_config(expiry: u64, valid_until: u64) -> Config {
        Config {
            passport: PassportPolicy {
                epoch: 7,
                valid_until: expiry,
                gates: [GateId::new("global-test").unwrap()].into(),
            },
            valid_until,
            challenge_lifetime: 60,
        }
    }

    async fn blind_holder(rng: &mut StdRng, expiry: u64, epoch: u64) -> Passport {
        let gate = GateId::new("global-test").unwrap();
        let issuer = IssuerKey::generate(
            rng,
            KeyId::new("shared-issuer").unwrap(),
            vec![gate.clone()],
        )
        .unwrap();
        let secret = HolderSecret::generate(rng);
        let store = cpsd::MemoryStore::new(cpsd::CommunityId::new("issuer").unwrap(), 10).unwrap();
        let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
        let challenge = issuance_challenge(rng, &store, issuer.public_key(), &auth, NOW + 60)
            .await
            .unwrap();
        let (request, pending) =
            request_issue(rng, &secret, issuer.public_key(), &challenge).unwrap();
        let blind = issue_blind_once(
            rng,
            &store,
            &issuer,
            &auth,
            &request,
            &challenge,
            &PassportAttributes::new(expiry, epoch).with_gate(gate, expiry),
            NOW,
        )
        .await
        .unwrap();
        pending.finish(&blind).unwrap()
    }

    /// Minimal real engine: migrated database, real membership/gate/policy
    /// facades and a blind holder identity. No passkey ceremony is performed;
    /// these tests exercise begin/snapshot paths that need no authentication.
    async fn test_engine() -> (TestEngine, crlt::Db, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let db = test_db(&directory).await;
        let clock = Clock(Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(42);
        let holder = blind_holder(&mut rng, EXPIRY, 7).await;
        let rules = test_rulebook();
        let store = crate::adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
        let signer = csgn::PersistentSigner::create(
            csgn::LibsqlStore::new(db.community("example").unwrap()),
            "example",
            csgn::SecretKey::from_seed(&mut [1; 32]),
            NOW,
            ESTABLISHED_MEMBER_LIFETIME,
        )
        .await
        .unwrap();
        let mut policy = cplc::Policy::create(
            store,
            cplc::LibsqlStore::new(&db, "example").unwrap(),
            signer,
            cplc::Config {
                credential_action: ADMISSION_ACTION.into(),
                snapshot_validity: 86_400,
            },
        )
        .await
        .unwrap();
        policy
            .schedule_rules(
                None,
                crbk::Change {
                    rulebook: rules,
                    announced_at: NOW as i64,
                    effective_at: NOW as i64,
                    notice_seconds: 0,
                    policy_epoch: 1,
                },
            )
            .await
            .unwrap();
        policy.set_schema(test_schema()).await.unwrap();
        let configuration = test_config(EXPIRY, EXPIRY);
        let engine = Community::new(
            crate::storage::MemoryStorage::new(cpsd::CommunityId::new("example").unwrap(), 32)
                .unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: cmbr::Membership::new(
                    &db,
                    cmbr::LibsqlStorage::new(&db, "example").unwrap(),
                    cmbr::Config {
                        pending_days: 2,
                        lease_months: 12,
                        membership_action: ADMISSION_ACTION.into(),
                        release_period: crgs::ReleasePeriod::default(),
                        rp_id: "members.example.org".into(),
                        origins: vec![ckyh::Url::parse(ORIGIN).unwrap()],
                    },
                    Authority,
                    clock,
                )
                .unwrap(),
                gates: cgts::Gatekeeper::new(
                    cgts::LibsqlStore::new(&db, "example").unwrap(),
                    cgts::LegalGate::new(
                        cgts::legal_storage::LibsqlStore::new(&db, "example").unwrap(),
                        Authority,
                    ),
                )
                .unwrap(),
                policy,
            },
            configuration,
        )
        .unwrap();
        (engine, db, directory)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn challenge_accessors_match_authenticated_request_and_verified_holder() {
        let (engine, _db, _directory) = test_engine().await;
        // Reproduce the fixture's issuer and holder through real blind issuance.
        let mut rng = StdRng::seed_from_u64(42);
        let holder = blind_holder(&mut rng, EXPIRY, 7).await;
        let challenge = engine.begin(&mut rng, NOW).await.unwrap();
        let snapshot = engine.snapshot(NOW).await.unwrap();
        let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
            engine.community().clone(),
            snapshot.signing_keys,
        );
        let signed: fn(&Challenge) -> &[u8] = std::hint::black_box(Challenge::signed_request);
        let request: fn(&Challenge) -> &PresentationRequest =
            std::hint::black_box(Challenge::request);
        let authenticated = origin.authenticate(signed(&challenge), NOW).unwrap();
        assert_eq!(request(&challenge).to_bytes(), authenticated.to_bytes());
        let proof = holder
            .present(&mut rng, &origin, signed(&challenge), NOW)
            .unwrap();
        let verified = engine
            .verify(&mut rng, &challenge, &proof, NOW)
            .await
            .unwrap();
        let member: fn(&VerifiedPassport) -> &str =
            std::hint::black_box(VerifiedPassport::member_id);
        assert_eq!(
            member(&verified),
            holder.pseudonym(engine.community()).to_hex()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn begin_rejects_poisoned_config_lock() {
        let (engine, _db, _directory) = test_engine().await;
        // Premise: a fresh engine holds no revocation events, so begin writes
        // nothing before the config read; the snapshot path is read-only.
        assert!(
            engine
                .membership()
                .revocations(256)
                .await
                .unwrap()
                .is_empty()
        );
        // Poison the config lock by holding its write guard across a panic in
        // a scoped thread. Update/refresh never hold the guard across await,
        // so no public flow can poison it; this is the only way to reach the
        // RwLock failure mapping at community.rs:178.
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let _guard = engine.config.write().unwrap();
                panic!("poison config lock for coverage");
            });
            let _ = handle.join();
        });
        assert!(engine.config.read().is_err());
        let mut rng = StdRng::seed_from_u64(1);
        assert!(matches!(
            engine.begin(&mut rng, NOW).await,
            Err(Error::Policy)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_unchanged_detects_each_field_difference() {
        let (engine, _db, _directory) = test_engine().await;
        let base = engine.snapshot(NOW).await.unwrap();
        assert!(base.unchanged(&base));
        let mut other = base.clone();
        other.rules.community = "other".into();
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.rules.revision = base.rules.revision.wrapping_add(1);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.rules.policy_epoch = base.rules.policy_epoch.wrapping_add(1);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other
            .rules
            .content
            .insert("coverage-probe".into(), serde_json::json!(true));
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.schema_version = base.schema_version.wrapping_add(1);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.passport.epoch = base.passport.epoch.wrapping_add(1);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.passport.valid_until = base.passport.valid_until.wrapping_add(86_400);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.passport.gates.clear();
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        let mut other = base.clone();
        other.valid_until = base.valid_until.wrapping_add(1);
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
        engine
            .policy()
            .lock()
            .await
            .rotate(csgn::SecretKey::from_seed(&mut [8; 32]), NOW)
            .await
            .unwrap();
        let rotated = engine.snapshot(NOW).await.unwrap();
        assert!(base.signing_keys.to_cbor() != rotated.signing_keys.to_cbor());
        let mut other = base.clone();
        other.signing_keys = rotated.signing_keys.clone();
        assert!(!base.unchanged(&other));
        assert!(!other.unchanged(&base));
    }
}
