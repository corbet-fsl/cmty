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
}

pub(super) struct MemberCommit<M, L, C, R, P, K> {
    membership: cmbr::Membership<M, L, C>,
    authentication: Arc<ckyh::Authentication>,
    session: Arc<dyn AccountSession>,
    runtime: tokio::runtime::Handle,
    state: Mutex<State<R, P, K>>,
}
impl<M, L, C, R, P, K> MemberCommit<M, L, C, R, P, K> {
    pub(super) fn new(
        membership: cmbr::Membership<M, L, C>,
        authentication: Arc<ckyh::Authentication>,
        session: Arc<dyn AccountSession>,
        state: State<R, P, K>,
    ) -> Self {
        Self {
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
