//! Original current member intake and guarded common checkpoint publication.
use super::*;
use cgts::cblc::{enrollment::*, storage::CommitAuthority};
use std::sync::{Arc, Mutex};

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
    /// Configure the original common publisher alongside the one actual ledger.
    /// Both caller-owned stores must belong to this community; the native install
    /// additionally checks exact operator, immutable digest and checkpoint period.
    pub async fn with_account_enrollment<V, Clock, E>(
        mut self,
        service: cgts::cblc::accounting_service::AccountService<V, Clock>,
        enrollment: EnrollmentService<E>,
    ) -> Result<Self>
    where
        V: cgts::cblc::accounting::AccountProofVerifier + Send + 'static,
        Clock: Fn() -> u64 + Send + 'static,
        E: Fn() -> u64 + Send + 'static,
    {
        self.gates = self
            .gates
            .with_account_enrollment(service, enrollment)
            .await
            .map_err(installation_error)?;
        Ok(self)
    }

    /// Configure the same combined native owner, preserving its exact proof
    /// cancellation and mandatory worker join. Retain account_shutdown externally.
    pub async fn with_native_account_enrollment<Clock, E>(
        mut self,
        service: cgts::cblc::accounting_service::AccountService<
            cgts::cblc::accounting_service::NativeAccountVerifier,
            Clock,
        >,
        enrollment: EnrollmentService<E>,
    ) -> Result<Self>
    where
        Clock: Fn() -> u64 + Send + 'static,
        E: Fn() -> u64 + Send + 'static,
    {
        self.gates = self
            .gates
            .with_native_account_enrollment(service, enrollment)
            .await
            .map_err(installation_error)?;
        Ok(self)
    }

    /// Submit the original device-authorized delegation for the actual current
    /// member. Request data cannot choose member identity, host trust or a root.
    /// The returned immutable registry entry is not an installation capability.
    pub async fn enroll_account(
        &self,
        auth: Arc<ckyh::Authentication>,
        delegation: AccountingDelegation,
        now: u64,
        session: Arc<dyn AccountSession>,
    ) -> Result<EnrollmentEntry> {
        let prepared = self
            .prepare_account_member(auth, &delegation.admission, now, session, true)
            .await?;
        let context = cgts::Context {
            snapshot: &prepared.settings,
            subject: &prepared.subject,
            action: "community.account",
            now: now as i64,
        };
        self.gates
            .enroll_account(
                context,
                prepared.pseudonym,
                delegation,
                prepared.expected.ok_or(Error::Policy)?,
                prepared.authority,
            )
            .await
            .map_err(host_error)
    }

    /// Freeze, install and acknowledge the original common roster on the SAME
    /// configured worker. The held Policy owner is reused at source and target;
    /// no recursive Policy acquisition occurs while opaque capabilities retain it.
    /// Success returns historical signed data, not a renewed target authority.
    /// All captured guards drop before the caller can sign another Policy feed.
    pub async fn publish_account_checkpoint(
        &self,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<EnrollmentPublication> {
        let (current, expected) = self.capture_checkpoint(clock).await?;
        let (response, _) = self
            .gates
            .account_host(
                cgts::HostRequest::PrepareCheckpoint {
                    expected,
                    authority: current.clone(),
                },
                current.clone(),
            )
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::PendingCheckpoint(pending) = response else {
            return Err(Error::Reconcile);
        };
        let (response, _) = self
            .gates
            .account_host(
                cgts::HostRequest::InstallCheckpoint {
                    pending,
                    authority: current.clone(),
                },
                current.clone(),
            )
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::InstalledCheckpoint(installed) = response else {
            return Err(Error::Reconcile);
        };
        let (response, _) = self
            .gates
            .account_host(
                cgts::HostRequest::AcknowledgeCheckpoint(installed),
                current.clone(),
            )
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::EnrollmentCheckpoint(Some(publication)) = response else {
            return Err(Error::Reconcile);
        };
        // The receipt is historical. Do not imply an additional target authority
        // observation after acknowledgement or renew its original interval.
        Ok(publication)
    }

    /// Retrieve the original common public object. None publishes the actual
    /// current slot; Some reads ONLY installed retained history or absence.
    /// Same-slot frozen context is never renewed G1 or target authority.
    pub async fn account_checkpoint(
        &self,
        slot: Option<u64>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Option<EnrollmentPublication>> {
        let Some(slot) = slot else {
            return self.publish_account_checkpoint(clock).await.map(Some);
        };
        let (current, _) = self.capture_checkpoint(clock).await?;
        let (response, current) = self
            .gates
            .account_host(cgts::HostRequest::EnrollmentCheckpoint { slot }, current)
            .await
            .map_err(host_error)?;
        let cgts::HostResponse::EnrollmentCheckpoint(publication) = response else {
            return Err(Error::Reconcile);
        };
        // The same held Policy returns from the worker. Do not reacquire its
        // outer mutex or treat these public bytes as an installation receipt.
        let owned = Arc::try_unwrap(current).map_err(|_| Error::Reconcile)?;
        let state = owned.state.into_inner().map_err(|_| Error::Reconcile)?;
        if !state.valid {
            return Err(Error::Reconcile);
        }
        let mut observed = state.observed;
        let now = host_time(&owned.clock, &mut observed)?;
        ensure_unchanged(
            &state.snapshot,
            &self.snapshot_locked(&state.policy, now).await?,
        )?;
        let expected = authority::current_enrollment(&state.policy, &state.snapshot, now).await?;
        if !same_expectation(&expected, &state.expected)
            || now
                >= state
                    .snapshot
                    .valid_until
                    .min(state.snapshot.passport.valid_until)
            || host_time(&owned.clock, &mut observed)? != now
        {
            return Err(Error::Reconcile);
        }
        Ok(publication)
    }

    async fn capture_checkpoint<Clock>(
        &self,
        clock: Clock,
    ) -> Result<(
        Arc<PublisherCommit<R, P, K, Clock>>,
        cgts::EnrollmentExpected,
    )>
    where
        Clock: Fn() -> u64 + Send + Sync + 'static,
    {
        let mut observed = 0;
        let now = host_time(&clock, &mut observed)?;
        self.flush_revocations(now).await?;
        host_time(&clock, &mut observed)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock, &mut observed)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        let now = host_time(&clock, &mut observed)?;
        let expected = authority::current_enrollment(&policy, &snapshot, now).await?;
        host_time(&clock, &mut observed)?;
        let current = Arc::new(PublisherCommit {
            runtime: tokio::runtime::Handle::current(),
            clock,
            state: Mutex::new(PublisherState {
                policy,
                snapshot,
                expected: expected.clone(),
                observed,
                valid: true,
            }),
        });
        Ok((current, expected))
    }
}

fn installation_error(error: cgts::Error) -> Error {
    match error {
        cgts::Error::Scope => Error::Scope,
        cgts::Error::Storage => Error::Storage,
        _ => Error::Gate,
    }
}

struct PublisherState<R: crbk::Storage, P: cplc::Storage, K: csgn::Store> {
    policy: tokio::sync::OwnedMutexGuard<cplc::Policy<R, P, K>>,
    snapshot: PolicySnapshot,
    expected: cgts::EnrollmentExpected,
    observed: u64,
    valid: bool,
}
struct PublisherCommit<R: crbk::Storage, P: cplc::Storage, K: csgn::Store, C> {
    runtime: tokio::runtime::Handle,
    clock: C,
    state: Mutex<PublisherState<R, P, K>>,
}
impl<R, P, K, C> CommitAuthority for PublisherCommit<R, P, K, C>
where
    R: crbk::Storage + Send + 'static,
    P: cplc::Storage + Send + 'static,
    K: csgn::Store + Send + 'static,
    C: Fn() -> u64 + Send + Sync,
{
    fn check(&self, observed: u64) -> std::result::Result<(), cgts::cblc::Error> {
        let mut state = self.state.lock().map_err(|_| cgts::cblc::Error::Storage)?;
        if !state.valid || observed < state.observed || (self.clock)() != observed {
            state.valid = false;
            return Err(cgts::cblc::Error::Admission);
        }
        state.valid = false;
        self.runtime
            .block_on(async {
                if observed
                    >= state
                        .snapshot
                        .valid_until
                        .min(state.snapshot.passport.valid_until)
                {
                    return Err(Error::Time);
                }
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
                let current =
                    authority::current_enrollment(&state.policy, &state.snapshot, observed).await?;
                if current.trust.community_id != state.expected.trust.community_id
                    || current.trust.policy_digest != state.expected.trust.policy_digest
                    || current.trust.policy_keys.to_cbor()
                        != state.expected.trust.policy_keys.to_cbor()
                    || current.policy_epoch != state.expected.policy_epoch
                    || current.passport_policy_digest != state.expected.passport_policy_digest
                    || (self.clock)() != observed
                {
                    return Err(Error::Policy);
                }
                Ok(())
            })
            .map_err(|_| cgts::cblc::Error::Admission)?;
        state.observed = observed;
        state.valid = true;
        Ok(())
    }
}

fn same_expectation(a: &cgts::EnrollmentExpected, b: &cgts::EnrollmentExpected) -> bool {
    a.trust.community_id == b.trust.community_id
        && a.trust.policy_digest == b.trust.policy_digest
        && a.trust.policy_keys.to_cbor() == b.trust.policy_keys.to_cbor()
        && a.policy_epoch == b.policy_epoch
        && a.passport_policy_digest == b.passport_policy_digest
}
