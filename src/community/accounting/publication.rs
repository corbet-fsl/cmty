//! One original Policy/Beacon completion path with its retained native guard.
use super::*;

pub(super) struct PublicationState<R: crbk::Storage, P: cplc::Storage, K: csgn::Store> {
    pub(super) policy: tokio::sync::OwnedMutexGuard<cplc::Policy<R, P, K>>,
    pub(super) snapshot: PolicySnapshot,
    pub(super) period_key: String,
    pub(super) period_seconds: u64,
    pub(super) version: cplc::cbcn::document::Version,
    pub(super) floor: u64,
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
    pub(super) async fn complete_account_publication(
        &self,
        state: PublicationState<R, P, K>,
        native: (
            Option<cgts::cblc::accounting_ledger::record_epoch::RecordEpochPublication>,
            cgts::cblc::publication::PublicVerifierMaterial,
        ),
        clock: &(impl Fn() -> u64 + Send + Sync),
    ) -> Result<(
        Option<cgts::cblc::accounting_ledger::record_epoch::RecordEpochPublication>,
        std::sync::Arc<cplc::cbcn::Feed>,
    )> {
        let PublicationState {
            mut policy,
            snapshot,
            period_key,
            period_seconds,
            version,
            mut floor,
        } = state;
        let (publication, material) = native;
        async {
            let now = host_time(clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(clock, &mut floor)?;
            let current_period = policy
                .record_epoch_settings(&period_key, now)
                .await
                .map_err(policy_error)?;
            let now = host_time(clock, &mut floor)?;
            let current_version = policy.balance_version(now).await.map_err(policy_error)?;
            let now = host_time(clock, &mut floor)?;
            if current_period.period_seconds != period_seconds
                || current_version.epoch != version.epoch
                || current_version.revision != version.revision
                || material.policy_epoch != version.epoch
                || material.revision != version.revision
                || publication.as_ref().is_some_and(|published| {
                    material.record_epoch.as_ref() != Some(published.descriptor())
                })
            {
                return Err(Error::Reconcile);
            }
            let epoch_deadline = if let Some(epoch) = &material.record_epoch {
                if epoch.expires_at.checked_sub(epoch.starts_at) != Some(period_seconds) {
                    return Err(Error::Reconcile);
                }
                epoch.check_time(now).map_err(|_| Error::Reconcile)?;
                epoch.expires_at
            } else {
                material.policy.account.policy_valid_until
            };
            let material_deadline = material.policy.account.policy_valid_until;
            let settlement_deadline = if let Some(settings) = &material.settlement {
                settings.check_time(now).map_err(|_| Error::Reconcile)?;
                settings.epoch.valid_until / 1000
            } else {
                material_deadline
            };
            let balance = policy
                .publish_balance(material, now)
                .await
                .map_err(|_| Error::Reconcile)?;
            let now = host_time(clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(clock, &mut floor)?;
            let feed = policy
                .refresh_trust(now)
                .await
                .map_err(|_| Error::Reconcile)?;
            let now = host_time(clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(clock, &mut floor)?;
            let final_period = policy
                .record_epoch_settings(&period_key, now)
                .await
                .map_err(policy_error)?;
            let now = host_time(clock, &mut floor)?;
            if final_period.period_seconds != period_seconds
                || feed.policy_epoch != version.epoch
                || feed.balance.as_ref() != Some(&balance)
            {
                return Err(Error::Reconcile);
            }
            let signed = policy
                .key_ring()
                .map_err(policy_error)?
                .verify(&balance, csgn::Kind::SettingsSnapshot, now)
                .map_err(|_| Error::Reconcile)?;
            let deadline = snapshot
                .valid_until
                .min(snapshot.passport.valid_until)
                .min(material_deadline)
                .min(settlement_deadline)
                .min(epoch_deadline)
                .min(signed.valid_until());
            if host_time(clock, &mut floor)? >= deadline {
                return Err(Error::Reconcile);
            }
            Ok((publication, feed))
        }
        .await
        .map_err(|_| Error::Reconcile)
    }
}
