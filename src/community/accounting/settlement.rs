//! Trusted current Policy composition and session-free anonymous ingress.
use super::*;
use cgts::cblc::settlement::{
    SettlementConfig, SettlementIssuer, SettlementStatus, SettlementSubmission,
};
use std::sync::Arc;
mod current;

struct Unfinished(Option<cgts::AccountShutdown>);
impl Drop for Unfinished {
    fn drop(&mut self) {
        // Begin the SAME original cancellation/join without blocking a reactor.
        // The outer host must still await this handle outside its Community lock.
        if let Some(shutdown) = &self.0 {
            let _ = shutdown.begin_shutdown();
        }
    }
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
    /// Trusted configuration/upkeep only; never deserialize these keys, limits
    /// or the opaque private issuer from a member/anonymous endpoint. The
    /// application fixes both immutable catalogue keys independently. A possibly
    /// committed or abandoned tail fences the service; its host must await the
    /// retained shutdown handle before tearing down the shared storage runtime.
    pub async fn reconcile_account_settlement(
        &self,
        period_key: &str,
        quota_key: &str,
        config: SettlementConfig,
        issuer: SettlementIssuer,
        incarnation: String,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Arc<cplc::cbcn::Feed>> {
        let shutdown = self.account_shutdown()?;
        let clock_observation = || clock();
        let mut floor = 0;
        let now = host_time(&clock_observation, &mut floor)?;
        self.flush_revocations(now).await?;
        host_time(&clock_observation, &mut floor)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock_observation, &mut floor)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        let now = host_time(&clock_observation, &mut floor)?;
        let period = policy
            .record_epoch_settings(period_key, now)
            .await
            .map_err(policy_error)?;
        let now = host_time(&clock_observation, &mut floor)?;
        let quota = policy
            .outcome_quota_settings(quota_key, now)
            .await
            .map_err(policy_error)?;
        let now = host_time(&clock_observation, &mut floor)?;
        let version = policy.balance_version(now).await.map_err(policy_error)?;
        let now = host_time(&clock_observation, &mut floor)?;
        ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
        host_time(&clock_observation, &mut floor)?;
        if config.epoch.community != snapshot.rules.community
            || config.policy_epoch != version.epoch
            || snapshot.rules.policy_epoch != version.epoch
            || config.period_seconds != period.period_seconds
            || config.quota != quota.quota
            || issuer.epoch() != &config.epoch
        {
            return Err(Error::Policy);
        }
        let state = current::Current::new(
            publication::PublicationState {
                policy,
                snapshot,
                period_key: period_key.into(),
                period_seconds: period.period_seconds,
                version,
                floor,
            },
            config.clone(),
            quota_key.into(),
            clock.clone(),
        );
        // Arm before queueing. Dropping this future retains actual Policy on the
        // worker but irreversibly fences/cancels the original native service.
        let mut unfinished = Unfinished(Some(shutdown));
        let (response, state) = self
            .gates
            .account_host(
                cgts::HostRequest::ReconcileSettlement {
                    config,
                    issuer,
                    incarnation,
                    revision: version.revision,
                    authority: state.clone(),
                },
                state,
            )
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::VerifierMaterial(material) = response else {
            return Err(Error::Reconcile);
        };
        let state = state.into_publication()?;
        let (_, feed) = self
            .complete_account_publication(state, (None, material), &clock_observation)
            .await?;
        drop(unfinished.0.take());
        Ok(feed)
    }

    /// Anonymous native ingress on the SAME configured owner. No member,
    /// authentication session, contact or source-role data enters this method.
    /// Staged means durable verified facts awaiting the original next daily cut;
    /// it never claims inbox effects or a published G2 before that atomic cut.
    pub async fn stage_account_settlement(
        &self,
        submission: SettlementSubmission,
    ) -> Result<SettlementStatus> {
        let (response, ()) = self
            .gates
            .account_host(cgts::HostRequest::StageSettlement(submission), ())
            .await
            .map_err(host_error)?;
        match response {
            cgts::HostResponse::Settlement(status) => Ok(status),
            _ => Err(Error::Reconcile),
        }
    }
}
