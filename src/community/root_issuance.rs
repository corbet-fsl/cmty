//! In-process common purpose issuer. Role authority never crosses a wire.
use super::*;
use std::sync::Arc;

mod begin;
mod finish;

/// Root-owned purpose key and original bounded root nonce store. The host may
/// share this opaque owner with source communities; it must not copy its key
/// into source configuration or substitute the global passport issuer.
/// There is deliberately no direct signing method or private-key accessor.
pub struct RootBoardIssuer<T, R, P, K> {
    store: T,
    key: cpsd::IssuerKey,
    policy: Arc<Mutex<cplc::Policy<R, P, K>>>,
}

impl<T: ChallengeStore, R: crbk::Storage, P: cplc::Storage, K: csgn::Store>
    RootBoardIssuer<T, R, P, K>
{
    /// Install an explicitly provisioned ROOT purpose key. `store` must share
    /// the root's original challenge database, and `policy` must be its actual
    /// serialized Policy owner. No source/community/member request configures it.
    async fn new(
        store: T,
        key: cpsd::IssuerKey,
        policy: Arc<Mutex<cplc::Policy<R, P, K>>>,
        now: u64,
    ) -> Result<Self> {
        check_time(now)?;
        if store.community().as_bytes() != b"root" {
            return Err(Error::Scope);
        }
        let owner = Self { store, key, policy };
        owner.current(&*owner.policy.lock().await, now).await?;
        Ok(owner)
    }

    async fn current(
        &self,
        policy: &cplc::Policy<R, P, K>,
        now: u64,
    ) -> Result<(cpsd::RootBoardPublicKey, u64)> {
        let (descriptor, until) = policy
            .root_board_descriptor(now)
            .await
            .map_err(policy_error)?
            .ok_or(Error::Policy)?;
        if policy.key_ring().map_err(policy_error)?.issuer() != "root"
            || descriptor.community() != self.store.community()
            || descriptor.issuer() != self.key.public_key()
            || now >= until
        {
            return Err(Error::Policy);
        }
        Ok((descriptor, until))
    }
}

/// Non-wire input from the actual garden authentication owner. The host retains
/// the original session guard while using this input; an expiry copied from a
/// submitted body is never session authority.
pub struct RootBoardSession<'a, F> {
    /// Genuine original community-local passkey authentication.
    pub authentication: &'a ckyh::Authentication,
    /// Original session's exclusive expiry; never the proof's expiry.
    pub valid_until: u64,
    /// Direct live owner clock, sharing the membership observation floor.
    pub clock: F,
}

/// Service-retained exact context. Only the two signed public messages travel
/// to the holder; no source role or member history is added to root storage.
pub struct RootBoardChallenge {
    context: cpsd::RootBoardIssuanceContext,
    source_signature: Vec<u8>,
    root_signature: Vec<u8>,
    source_policy: PolicySnapshot,
    checked_at: u64,
}

impl RootBoardChallenge {
    /// Root Policy's authenticated original context.
    pub fn signed_context(&self) -> &[u8] {
        &self.root_signature
    }
    /// Source Policy's authenticated original passport request.
    pub fn signed_source_request(&self) -> &[u8] {
        &self.source_signature
    }
    /// Exclusive host lifetime corresponding to CPSD's inclusive context and
    /// nonce-store deadline. Construction caps that deadline strictly below
    /// every exclusive authority bound and CPSD's finite timestamp limit.
    pub fn valid_until(&self) -> u64 {
        self.context.deadline() + 1
    }
}

fn source_role(lease: &cmbr::RoleLease, community: &CommunityId) -> Result<()> {
    if lease.community().as_bytes() != community.as_bytes()
        || !matches!(lease.role(), crgs::Role::Admin | crgs::Role::Root)
    {
        return Err(Error::Membership);
    }
    Ok(())
}

struct LiveTime<'a, F> {
    clock: &'a F,
    observed: u64,
}

impl<'a, F: Fn() -> u64> LiveTime<'a, F> {
    fn new(clock: &'a F, floor: u64) -> Result<Self> {
        let mut value = Self {
            clock,
            observed: floor,
        };
        value.observe()?;
        Ok(value)
    }

    fn observe(&mut self) -> Result<u64> {
        let now = (self.clock)();
        check_time(now)?;
        if now < self.observed {
            return Err(Error::Time);
        }
        self.observed = now;
        Ok(now)
    }

    fn release(
        &mut self,
        lease: &cmbr::RoleLease,
        context: &cpsd::RootBoardIssuanceContext,
    ) -> Result<u64> {
        let now = self.observe()?;
        if now > context.deadline() || !lease.is_current(now) {
            return Err(Error::Time);
        }
        Ok(now)
    }
}
