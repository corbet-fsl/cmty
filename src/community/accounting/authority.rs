//! Final member authority at the actual native accounting commit decision.
use super::*;
use cgts::cblc::{admission::AdmissionGrant, storage::CommitAuthority};
use std::sync::{Arc, Mutex};

/// Original live host session, retained through native work and cancellation.
/// The implementation owns actual session invalidation and the SAME live clock;
/// it never reacquires the outer Community mutex from the accounting worker.
/// This trusted application port is not a wire object or a replaceable verifier.
pub trait AccountSession: Send + Sync {
    /// Original exclusive expiry; cancellation cannot renew it.
    fn valid_until(&self) -> u64;
    /// Refuse an invalidated/replaced session, clock change or expiry. The
    /// actual host clock must still equal the native owner's observed second.
    fn check(&self, observed: u64) -> Result<()>;
}

pub(super) struct State<R, P, K> {
    pub(super) lease: cmbr::SourceLease,
    pub(super) policy: tokio::sync::OwnedMutexGuard<cplc::Policy<R, P, K>>,
    pub(super) snapshot: PolicySnapshot,
    pub(super) grant: AdmissionGrant,
    pub(super) observed: u64,
    pub(super) valid: bool,
    pub(super) enrollment: Option<cgts::EnrollmentExpected>,
}

pub(super) struct MemberCommit<M, L, C, R, P, K> {
    membership: cmbr::Membership<M, L, C>,
    authentication: Arc<ckyh::Authentication>,
    session: Arc<dyn AccountSession>,
    runtime: tokio::runtime::Handle,
    state: Mutex<State<R, P, K>>,
    /// The member's Active device keys as the registry listed them when the request was
    /// prepared. The commit-time `check` re-reads the registry; this snapshot only mints the
    /// `CurrentDevice` witness that cblc's update entry points require.
    devices: Vec<[u8; 32]>,
}

impl<M, L, C, R, P, K> cgts::cblc::current_device::CurrentLineage
    for MemberCommit<M, L, C, R, P, K>
{
    fn is_current(&self, device: &[u8; 32]) -> bool {
        self.devices.contains(device)
    }
}

impl<M, L, C, R, P, K> MemberCommit<M, L, C, R, P, K> {
    pub(super) fn new(
        membership: cmbr::Membership<M, L, C>,
        authentication: Arc<ckyh::Authentication>,
        session: Arc<dyn AccountSession>,
        state: State<R, P, K>,
        devices: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            devices,
            membership,
            authentication,
            session,
            runtime: tokio::runtime::Handle::current(),
            state: Mutex::new(state),
        }
    }
}

impl<M, L, C, R, P, K> CommitAuthority for MemberCommit<M, L, C, R, P, K>
where
    M: cmbr::Storage + Send + Sync + 'static,
    L: clbs::Verifier + Send + Sync + 'static,
    C: clbs::Clock + Send + Sync + 'static,
    R: crbk::Storage + Send + 'static,
    P: cplc::Storage + Send + 'static,
    K: csgn::Store + Send + 'static,
{
    fn lineage(&self) -> Option<&dyn cgts::cblc::current_device::CurrentLineage> {
        Some(self)
    }
    fn check(&self, observed: u64) -> std::result::Result<(), cgts::cblc::Error> {
        let mut state = self.state.lock().map_err(|_| cgts::cblc::Error::Storage)?;
        if !state.valid || observed < state.observed {
            return Err(cgts::cblc::Error::Admission);
        }
        // Error/panic cannot leave a reusable old authority observation.
        state.valid = false;
        self.runtime
            .block_on(async {
                self.session.check(observed)?;
                if observed >= self.session.valid_until()
                    || observed >= state.grant.expires_at
                    || observed >= state.snapshot.valid_until
                    || observed >= state.snapshot.passport.valid_until
                {
                    return Err(Error::Time);
                }
                // settings is the original READ-ONLY current owner method. Calling
                // verified_settings here could refresh/sign and acquire a writer.
                let rules = state
                    .policy
                    .settings(observed)
                    .await
                    .map_err(policy_error)?;
                if rules.community != state.snapshot.rules.community
                    || rules.revision != state.snapshot.rules.revision
                    || rules.policy_epoch != state.snapshot.rules.policy_epoch
                    || rules.content != state.snapshot.rules.content
                    || u64::from(
                        state
                            .policy
                            .schema()
                            .map_err(policy_error)?
                            .ok_or(Error::Policy)?
                            .version,
                    ) != state.snapshot.schema_version
                    || state.policy.key_ring().map_err(policy_error)?.to_cbor()
                        != state.snapshot.signing_keys.to_cbor()
                {
                    return Err(Error::Policy);
                }
                let facts = self
                    .membership
                    .check_source(
                        &mut state.lease,
                        &self.authentication,
                        "community.account",
                        observed,
                    )
                    .await
                    .map_err(member_error)?;
                let grant = &state.grant;
                let device = data_encoding::BASE64URL_NOPAD
                    .decode(grant.chat_public_key.as_bytes())
                    .map_err(|_| Error::Membership)?;
                let device: [u8; 32] = device.try_into().map_err(|_| Error::Membership)?;
                if facts.community != grant.community_id
                    || facts.member != grant.pseudonym
                    || facts.state != crbk::MembershipState::Admitted
                    || facts.lease_end < grant.expires_at
                    || !facts.authorized_devices.contains(&device)
                    || grant.policy_epoch != rules.policy_epoch
                    || grant.passport_policy_digest
                        != data_encoding::BASE64URL_NOPAD.encode(&state.snapshot.passport.digest())
                {
                    return Err(Error::Membership);
                }
                if let Some(expected) = &state.enrollment {
                    let current =
                        current_enrollment(&state.policy, &state.snapshot, observed).await?;
                    if current.trust.community_id != expected.trust.community_id
                        || current.trust.policy_digest != expected.trust.policy_digest
                        || current.trust.policy_keys.to_cbor()
                            != expected.trust.policy_keys.to_cbor()
                        || current.policy_epoch != expected.policy_epoch
                        || current.passport_policy_digest != expected.passport_policy_digest
                    {
                        return Err(Error::Policy);
                    }
                }
                // The captured owned Policy lock also excludes every actual
                // Community global-cohort update. Session invalidation is separate.
                self.session.check(observed)?;
                Ok(())
            })
            .map_err(|_| cgts::cblc::Error::Admission)?;
        state.observed = observed;
        state.valid = true;
        Ok(())
    }
}

pub(super) struct Prepared {
    pub(super) settings: crbk::Snapshot,
    pub(super) subject: String,
    pub(super) pseudonym: cpsd::Pseudonym,
    pub(super) authority: Arc<dyn CommitAuthority>,
    pub(super) expected: Option<cgts::EnrollmentExpected>,
}

impl<S, M, L, C, G, A, R, P, K> Community<S, M, L, C, G, A, R, P, K>
where
    S: Storage,
    M: cmbr::Storage + Send + Sync + 'static,
    L: clbs::Verifier + Send + Sync + 'static,
    C: clbs::Clock + Send + Sync + 'static,
    G: cgts::Storage,
    A: cgts::LegalVeto,
    R: crbk::Storage + Send + 'static,
    P: cplc::Storage + Send + 'static,
    K: csgn::Store + Send + 'static,
{
    pub(super) async fn prepare_account_member(
        &self,
        auth: Arc<ckyh::Authentication>,
        grant: &AdmissionGrant,
        now: u64,
        session: Arc<dyn AccountSession>,
        enrollment: bool,
    ) -> Result<Prepared> {
        check_time(now)?;
        session.check(now)?;
        if now >= session.valid_until() {
            return Err(Error::Time);
        }
        self.flush_revocations(now).await?;
        let mut policy = self.policy.clone().lock_owned().await;
        let configuration = self.snapshot_locked(&policy, now).await?;
        let snapshot = policy.verified_settings(now).await.map_err(policy_error)?;
        let row = self.membership.resume(&auth).await.map_err(member_error)?;
        let (facts, lease) =
            cplc::MembershipSource::membership(&self.membership, row.subject(), now)
                .await
                .map_err(|_| Error::Membership)?;
        // Revalidate the exact passkey after acquiring the member queue. This
        // read does not acquire a second lease or manufacture a credential.
        let current = self.membership.resume(&auth).await.map_err(member_error)?;
        if current.subject() != facts.member
            || facts.community != community_text(&self.community)?
            || facts.state != crbk::MembershipState::Admitted
            || facts.lease_end <= now
        {
            return Err(Error::Membership);
        }
        let bytes = data_encoding::HEXLOWER
            .decode(current.subject().as_bytes())
            .map_err(|_| Error::Membership)?;
        let pseudonym = cpsd::Pseudonym::from_bytes(&bytes).map_err(|_| Error::Membership)?;
        let device: [u8; 32] = data_encoding::BASE64URL_NOPAD
            .decode(grant.chat_public_key.as_bytes())
            .map_err(|_| Error::Membership)?
            .try_into()
            .map_err(|_| Error::Membership)?;
        if grant.community_id != facts.community
            || grant.pseudonym != current.subject()
            || grant.policy_epoch != snapshot.settings().policy_epoch
            || grant.passport_policy_digest
                != data_encoding::BASE64URL_NOPAD.encode(&configuration.passport.digest())
            || !facts.authorized_devices.contains(&device)
            || grant.issued_at > now
            || grant.expires_at <= now
            || grant.expires_at > facts.lease_end
            || grant.expires_at > snapshot.valid_until()
            || grant.expires_at > configuration.valid_until
            || grant.expires_at > configuration.passport.valid_until
        {
            return Err(Error::Membership);
        }
        let settings = snapshot.settings().clone();
        let subject = current.subject().to_owned();
        let expected = if enrollment {
            Some(current_enrollment(&policy, &configuration, now).await?)
        } else {
            None
        };
        let authority = std::sync::Arc::new(MemberCommit::new(
            self.membership.clone(),
            auth,
            session,
            State {
                lease,
                policy,
                snapshot: configuration,
                grant: grant.clone(),
                observed: now,
                valid: true,
                enrollment: expected.clone(),
            },
            facts.authorized_devices.clone(),
        ));
        Ok(Prepared {
            settings,
            subject,
            pseudonym,
            authority,
            expected,
        })
    }
}

pub(super) async fn current_enrollment<R, P, K>(
    policy: &cplc::Policy<R, P, K>,
    snapshot: &PolicySnapshot,
    now: u64,
) -> Result<cgts::EnrollmentExpected>
where
    R: crbk::Storage,
    P: cplc::Storage,
    K: csgn::Store,
{
    // The actual Policy verifies its retained full publication under current
    // epoch/counter and validates the owner format before returning these bytes.
    let bytes = policy
        .balance_publication(now)
        .await
        .map_err(policy_error)?
        .ok_or(Error::AccountUnavailable)?;
    let ring = policy.key_ring().map_err(policy_error)?;
    let signed = ring
        .verify(&bytes, csgn::Kind::SettingsSnapshot, now)
        .map_err(policy_error)?;
    let material: cgts::cblc::publication::PublicVerifierMaterial =
        serde_json::from_slice(signed.payload()).map_err(policy_error)?;
    material
        .validate_at(&snapshot.rules.community, now)
        .map_err(policy_error)?;
    if material.policy_epoch != snapshot.rules.policy_epoch {
        return Err(Error::Policy);
    }
    Ok(cgts::EnrollmentExpected {
        trust: cgts::cblc::admission::AdmissionTrust {
            community_id: snapshot.rules.community.clone(),
            policy_digest: data_encoding::BASE64URL_NOPAD.encode(&material.admission_policy_digest),
            policy_keys: ring.clone(),
        },
        policy_epoch: snapshot.rules.policy_epoch,
        passport_policy_digest: data_encoding::BASE64URL_NOPAD.encode(&snapshot.passport.digest()),
    })
}
