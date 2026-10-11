//! Complete member field change through the original native spend and pin owners.
use super::*;

/// Exact requested profile edit. Membership independently binds its community,
/// member and original pin; receipt bytes remain untrusted until native checking.
pub struct PinChange<'a> {
    /// Existing restricted field identifier selected under current Policy.
    pub field: &'a str,
    /// Exact observed revision and fingerprint, never a wildcard update.
    pub expected: cmbr::Pin,
    /// Original versioned device fingerprint, checked by Membership.
    pub replacement: &'a cmbr::PinV2,
    /// Bounded original request, acceptance and extended effect encoding.
    pub evidence: &'a [u8],
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
    /// Change a restricted field using one already committed native spend.
    /// The host supplies the actual live session's exclusive deadline and shared
    /// clock. No historical receipt lifetime can extend this authority.
    pub async fn change_pin(
        &self,
        auth: &ckyh::Authentication,
        change: PinChange<'_>,
        session_until: u64,
        clock: impl Fn() -> u64 + Send + Sync,
    ) -> Result<cmbr::Pin> {
        let mut floor = 0;
        let now = host_time(&clock, &mut floor)?;
        if now >= session_until {
            return Err(Error::Time);
        }
        self.flush_revocations(now).await?;
        host_time(&clock, &mut floor)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock, &mut floor)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        let schema = policy
            .schema()
            .map_err(policy_error)?
            .ok_or(Error::Policy)?;
        if !schema.public.iter().chain(&schema.private).any(|field| {
            field.id == change.field && field.change_preset != cplc::cshm::ChangePreset::Free
        }) {
            return Err(Error::Policy);
        }
        let until = session_until
            .min(snapshot.valid_until)
            .min(snapshot.passport.valid_until);
        if host_time(&clock, &mut floor)? >= until {
            return Err(Error::Time);
        }
        let pending = self
            .membership
            .prepare_pin_change(
                auth,
                change.field,
                change.expected,
                change.replacement,
                until,
            )
            .await
            .map_err(member_error)?;
        let request = pending
            .native_request(change.evidence)
            .map_err(member_error)?;
        if host_time(&clock, &mut floor)? >= until {
            return Err(Error::Time);
        }
        let (response, (pending, policy)) = self
            .gates
            .account_host(
                cgts::HostRequest::VerifyPinChange(request),
                (pending, policy),
            )
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::VerifiedPinChange(spent) = response else {
            return Err(Error::Gate);
        };
        let now = host_time(&clock, &mut floor)?;
        ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
        if host_time(&clock, &mut floor)? >= until {
            return Err(Error::Time);
        }
        let result = self
            .membership
            .finish_pin_change(auth, pending, &spent)
            .await;
        // Pin storage maps every possibly committed late/error outcome to its
        // uncertain category. Never treat it as an unspent accounting receipt.
        let pin = result.map_err(|error| match error {
            cmbr::Error::Unavailable => Error::Reconcile,
            other => member_error(other),
        })?;
        if host_time(&clock, &mut floor).map_err(|_| Error::Reconcile)? >= until {
            return Err(Error::Reconcile);
        }
        Ok(pin)
    }
}
