use chrono::{DateTime, Datelike};
use cpsd::{
    ChallengeStore, CommunityId, IssuerPublicKey, Presentation, PresentationRequest, Verifier,
    rand::{CryptoRng, RngCore},
};
use tokio::sync::Mutex;

use crate::{storage::Storage, *};

/// Server-held admission challenge. Only the request travels to the holder.
pub struct Challenge {
    request: PresentationRequest,
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
}

/// A consumed, verified passport presentation. No raw proof is retained.
/// Use it immediately to bind a first registration to its community pseudonym.
///
/// ```compile_fail
/// let raw: cpsd::Pseudonym = todo!();
/// let verified: cmnt::VerifiedPassport = raw.into();
/// ```
pub struct VerifiedPassport {
    member_id: String,
    witness: cgts::VerifiedPassport,
    community: CommunityId,
    policy: PolicySnapshot,
    verified_at: u64,
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
    /// A committed cpky login for the enrolled community-local user.
    pub authentication: &'a cpky::Authentication,
    /// Public device keys authorized by the service's device protocol.
    pub devices: &'a [[u8; 32]],
    /// Coarse lease end from the service's retention policy, not credential expiry.
    pub lease: crgs::YearMonth,
}

/// Community composition over cmbr, cgts and cplc. There is no local member
/// store, gate engine, policy evaluator, lifetime calculator or signer.
pub struct Community<S: Storage, M, L, C, G, A, R, P, K> {
    community: CommunityId,
    verifier: Verifier<S::Challenges>,
    membership: cmbr::Membership<M, L, C>,
    gates: cgts::Gatekeeper<G, A>,
    policy: Mutex<cplc::Policy<R, P, K>>,
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
        let store = storage.challenges();
        let community = store.community().clone();
        let name = community_text(&community)?;
        if parts.policy.key_ring().map_err(|_| Error::Policy)?.issuer() != name {
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
            verifier: Verifier::new(store, issuer_keys)?,
            membership: parts.membership,
            gates: parts.gates,
            policy: Mutex::new(parts.policy),
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
        self.flush_revocations(now).await?;
        let mut signer = self.policy.lock().await;
        let policy = self.snapshot_locked(&signer, now).await?;
        let lifetime = self
            .config
            .read()
            .map_err(|_| Error::Policy)?
            .challenge_lifetime;
        let deadline = now
            .checked_add(lifetime)
            .ok_or(Error::Time)?
            .min(policy.passport.valid_until - 1)
            .min(policy.valid_until - 1);
        if deadline <= now {
            return Err(Error::Time);
        }
        let request = self
            .verifier
            .request_for_epoch(
                rng,
                policy.passport.epoch,
                policy.passport.gates.iter().cloned(),
                deadline,
                policy.passport.valid_until,
            )
            .await?;
        let signed_request = signer
            .sign_presentation_request(&request, now)
            .await
            .map_err(|_| Error::Signing)?;
        Ok(Challenge {
            request,
            signed_request,
            policy,
            not_before: now,
        })
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
        if now < challenge.not_before || challenge.request.community() != &self.community {
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
        })
    }

    /// Consume a freshly verified passport and let cmbr start the passkey ceremony.
    /// The UUID is service-generated and community-local. Resume later through
    /// cmbr; final admission requires a new passport presentation and real login.
    pub async fn begin_registration(
        &self,
        passport: VerifiedPassport,
        user: cpky::Uuid,
        now: u64,
    ) -> Result<(cpky::CreationChallengeResponse, cmbr::PendingRegistration)> {
        if passport.community != self.community || passport.verified_at != now {
            return Err(Error::Passport);
        }
        if !passport.policy.unchanged(&self.snapshot(now).await?) {
            return Err(Error::Policy);
        }
        self.membership
            .begin_registration(user, &passport.member_id)
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
    /// Raw leaf inputs stay in this server callback, never in cmnt storage.
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
        let passport = self.verify(rng, challenge, presentation, now).await?;
        let snapshot = {
            let mut policy = self.policy.lock().await;
            if !passport
                .policy
                .unchanged(&self.snapshot_locked(&policy, now).await?)
            {
                return Err(Error::Policy);
            }
            policy
                .verified_settings(now)
                .await
                .map_err(|_| Error::Policy)?
        };
        let auth = admission.authentication;
        let row = match self.membership.resume(auth).await {
            Ok(row) => row,
            Err(cmbr::Error::Restricted) => return Ok(Outcome::Vetoed),
            Err(error) => return Err(member_error(error)),
        };
        if row.community() != community_text(&self.community)?
            || row.subject() != passport.member_id
        {
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
        checked.extend(passport.witness.gates(context).map_err(|_| Error::Gate)?);
        let checked = match self.gates.check(context, checked).await {
            Ok(checked) => checked,
            Err(cgts::Error::Vetoed) => return Ok(Outcome::Vetoed),
            Err(_) => return Err(Error::Gate),
        };
        let mut policy = self.policy.lock().await;
        if !passport
            .policy
            .unchanged(&self.snapshot_locked(&policy, now).await?)
        {
            return Err(Error::Policy);
        }
        policy
            .validate_snapshot(&snapshot, now)
            .await
            .map_err(|_| Error::Policy)?;
        let decision = policy
            .may(&snapshot, subject, ADMISSION_ACTION, &checked, now)
            .await
            .map_err(|_| Error::Policy)?;
        if !decision.allowed {
            // This explicit admission attempt may lapse an admitted row. Merely
            // rendering the cmbr lobby never performs this transition.
            self.membership
                .lapse(auth, &policy, &snapshot, &checked)
                .await
                .map_err(member_error)?;
            return Ok(Outcome::Missing(decision));
        }
        let admitted = self
            .membership
            .admit(auth, &policy, &snapshot, &checked, admission.lease)
            .await
            .map_err(member_error)?;
        let handle = self
            .membership
            .handle(auth)
            .await
            .map_err(member_error)?
            .ok_or(Error::Membership)?;
        let schema = policy
            .schema()
            .map_err(|_| Error::Policy)?
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
        if !passport
            .policy
            .unchanged(&self.snapshot_locked(&policy, now).await?)
        {
            return Err(Error::Policy);
        }
        // A cmbr commit can precede a signing failure. No bytes escape on failure;
        // retries start with a new presentation and do not change member class.
        let cose = policy
            .issue(
                &self.membership,
                cplc::CredentialRequest {
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
                },
                now,
            )
            .await
            .map_err(|error| match error {
                cplc::Error::Denied(_) | cplc::Error::Revoked => Error::Policy,
                _ => Error::Signing,
            })?;
        let verified = policy
            .key_ring()
            .map_err(|_| Error::Signing)?
            .verify(&cose, csgn::Kind::Credential, now)
            .map_err(|_| Error::Signing)?;
        let payload: cplc::Credential =
            serde_json::from_slice(verified.payload()).map_err(|_| Error::Signing)?;
        let claims = CredentialClaims {
            version: 1,
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
        Ok(Outcome::Issued(Box::new(IssuedCredential { claims, cose })))
    }

    /// Publish a conservative community epoch advance before acknowledging each
    /// membership event. A crash may repeat the advance, never lose revocation.
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
            policy.bump_epoch().await.map_err(|_| Error::Policy)?;
            policy
                .publish(cplc::SnapshotKind::Settings, now)
                .await
                .map_err(|_| Error::Policy)?;
            policy
                .publish(cplc::SnapshotKind::RevocationList, now)
                .await
                .map_err(|_| Error::Policy)?;
            for event in &events {
                self.membership
                    .acknowledge_revocation(event)
                    .await
                    .map_err(member_error)?;
            }
        }
        Ok(events.len())
    }

    /// Install authenticated global policy metadata after checking cglb's signed
    /// public status. Never source this from a holder. Epoch rollback is refused;
    /// the signing mutex excludes an update halfway through local issuance.
    pub async fn update_passport_policy(&self, passport: PassportPolicy) -> Result<()> {
        let _policy = self.policy.lock().await;
        let mut config = self.config.write().map_err(|_| Error::Policy)?;
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
        let mut config = self.config.write().map_err(|_| Error::Policy)?;
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
        let rules = policy.settings(now).await.map_err(|_| Error::Policy)?;
        let config = self.config.read().map_err(|_| Error::Policy)?.clone();
        let snapshot = PolicySnapshot {
            rules,
            schema_version: policy
                .schema()
                .map_err(|_| Error::Policy)?
                .ok_or(Error::Policy)?
                .version
                .into(),
            passport: config.passport,
            valid_until: config.valid_until,
            signing_keys: policy.key_ring().map_err(|_| Error::Policy)?.clone(),
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

fn check_time(now: u64) -> Result<()> {
    if now == 0
        || now >= cpsd::TIME_LIMIT
        || DateTime::from_timestamp(now as i64, 0).is_none_or(|date| date.year() > 9999)
    {
        return Err(Error::Time);
    }
    Ok(())
}
