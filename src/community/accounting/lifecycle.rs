//! Explicit host economic tuning on the original worker; never a member DTO.
use super::*;

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
    /// Apply an independently authorized operator waiting-period change to the
    /// same account service. No member request can select this operation. A
    /// possibly committed change whose final checks fail requires reconciliation;
    /// retry against the actual owner revision rather than rebuilding its ledger.
    pub async fn tune_account_waiting_period(
        &self,
        expected_revision: u64,
        seconds: u64,
        clock: impl Fn() -> u64 + Send + Sync,
    ) -> Result<cgts::cblc::accounting_ledger::WaitingPeriodTuning> {
        let mut floor = 0;
        let now = host_time(&clock, &mut floor)?;
        self.flush_revocations(now).await?;
        host_time(&clock, &mut floor)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock, &mut floor)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        host_time(&clock, &mut floor)?;
        let (response, policy) = self
            .gates
            .account_host(
                cgts::HostRequest::TuneWaiting {
                    expected_revision,
                    seconds,
                },
                policy,
            )
            .await
            .map_err(host_error)?;
        async {
            let cgts::HostResponse::WaitingPeriod(tuning) = response else {
                return Err(Error::Reconcile);
            };
            let now = host_time(&clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(&clock, &mut floor)?;
            if now >= snapshot.valid_until.min(snapshot.passport.valid_until) {
                return Err(Error::Reconcile);
            }
            Ok(tuning)
        }
        .await
        .map_err(|_| Error::Reconcile)
    }
}
