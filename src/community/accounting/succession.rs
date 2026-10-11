//! Actual held Policy continuity reconciles the same account worker.
use super::*;
use cgts::cblc::accounting_ledger::{AdmissionKeyReconciliation, AdmissionKeyState};

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
    /// Reconcile actual durable Policy rotation with the already-installed
    /// native ledger. No member-supplied ring, proof, revision or signer enters.
    /// Policy remains held through native work and final snapshot/clock checks;
    /// cancellation cannot release that authority before the worker finishes.
    pub async fn reconcile_account_admission_keys(
        &self,
        clock: impl Fn() -> u64 + Send + Sync,
    ) -> Result<AdmissionKeyState> {
        let mut floor = 0;
        let now = host_time(&clock, &mut floor)?;
        self.flush_revocations(now).await?;
        host_time(&clock, &mut floor)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock, &mut floor)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        host_time(&clock, &mut floor)?;
        let request = actual_target(&policy)?;
        let expected = request.target.clone();
        let (response, policy) = self
            .gates
            .account_host(cgts::HostRequest::ReconcileAdmissionKeys(request), policy)
            .await
            .map_err(host_error)?;
        async {
            let cgts::HostResponse::AdmissionKeys(installed) = response else {
                return Err(Error::Reconcile);
            };
            let now = host_time(&clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(&clock, &mut floor)?;
            if installed != expected
                || actual_target(&policy)?.target != expected
                || now >= snapshot.valid_until.min(snapshot.passport.valid_until)
            {
                return Err(Error::Reconcile);
            }
            Ok(installed)
        }
        .await
        .map_err(|_| Error::Reconcile)
    }
}

fn actual_target<R, P, K>(policy: &cplc::Policy<R, P, K>) -> Result<AdmissionKeyReconciliation>
where
    R: crbk::Storage,
    P: cplc::Storage,
    K: csgn::Store,
{
    // Policy owns the revision relation: key_transitions() checks durable signer
    // revision and pending acknowledgement against this exact retained history.
    let transitions = policy.key_transitions().map_err(policy_error)?;
    let target = AdmissionKeyState {
        revision: transitions.last().map_or(0, |item| item.revision),
        policy_keys: policy.key_ring().map_err(policy_error)?.clone(),
    };
    Ok(AdmissionKeyReconciliation {
        target,
        transitions: transitions
            .iter()
            .map(|item| (item.revision, item.proof.clone()))
            .collect(),
    })
}
