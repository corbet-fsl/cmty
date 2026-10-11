//! Retained actual Policy at the original daily owner writer decision.
use super::*;
use std::sync::Mutex;

struct State<R: crbk::Storage, P: cplc::Storage, K: csgn::Store> {
    publication: Option<publication::PublicationState<R, P, K>>,
    valid: bool,
}

pub(super) struct Current<R: crbk::Storage, P: cplc::Storage, K: csgn::Store> {
    state: Mutex<State<R, P, K>>,
    config: SettlementConfig,
    quota_key: String,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    runtime: tokio::runtime::Handle,
}

impl<R: crbk::Storage, P: cplc::Storage, K: csgn::Store> Current<R, P, K> {
    pub(super) fn new(
        publication: publication::PublicationState<R, P, K>,
        config: SettlementConfig,
        quota_key: String,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                publication: Some(publication),
                valid: true,
            }),
            config,
            quota_key,
            clock,
            runtime: tokio::runtime::Handle::current(),
        })
    }

    pub(super) fn into_publication(
        self: Arc<Self>,
    ) -> Result<publication::PublicationState<R, P, K>> {
        let owned = Arc::try_unwrap(self).map_err(|_| Error::Reconcile)?;
        let mut state = owned.state.into_inner().map_err(|_| Error::Reconcile)?;
        if !state.valid {
            return Err(Error::Reconcile);
        }
        state.publication.take().ok_or(Error::Reconcile)
    }
}

impl<R, P, K> cgts::cblc::storage::CommitAuthority for Current<R, P, K>
where
    R: crbk::Storage + Send + 'static,
    P: cplc::Storage + Send + 'static,
    K: csgn::Store + Send + 'static,
{
    fn check(&self, observed: u64) -> std::result::Result<(), cgts::cblc::Error> {
        let mut state = self.state.lock().map_err(|_| cgts::cblc::Error::Storage)?;
        if !state.valid {
            return Err(cgts::cblc::Error::Admission);
        }
        state.valid = false;
        let publication = state
            .publication
            .as_mut()
            .ok_or(cgts::cblc::Error::Admission)?;
        if observed < publication.floor
            || (self.clock)() != observed
            || observed
                >= publication
                    .snapshot
                    .valid_until
                    .min(publication.snapshot.passport.valid_until)
        {
            return Err(cgts::cblc::Error::Admission);
        }
        self.runtime
            .block_on(async {
                let policy = &publication.policy;
                // Original read-only owner methods use the remaining pool reader.
                // This callback never acquires the outer Community or another writer.
                let rules = policy.settings(observed).await.map_err(policy_error)?;
                if rules.community != publication.snapshot.rules.community
                    || rules.revision != publication.snapshot.rules.revision
                    || rules.policy_epoch != publication.snapshot.rules.policy_epoch
                    || rules.content != publication.snapshot.rules.content
                    || policy.key_ring().map_err(policy_error)?.to_cbor()
                        != publication.snapshot.signing_keys.to_cbor()
                    || u64::from(
                        policy
                            .schema()
                            .map_err(policy_error)?
                            .ok_or(Error::Policy)?
                            .version,
                    ) != publication.snapshot.schema_version
                {
                    return Err(Error::Policy);
                }
                let period = policy
                    .record_epoch_settings(&publication.period_key, observed)
                    .await
                    .map_err(policy_error)?;
                let quota = policy
                    .outcome_quota_settings(&self.quota_key, observed)
                    .await
                    .map_err(policy_error)?;
                if period.period_seconds != self.config.period_seconds
                    || period.period_seconds != publication.period_seconds
                    || quota.quota != self.config.quota
                    || rules.policy_epoch != self.config.policy_epoch
                    || publication.version.epoch != self.config.policy_epoch
                    || policy.epoch(observed).await.map_err(policy_error)?
                        != self.config.policy_epoch
                    || (self.clock)() != observed
                {
                    return Err(Error::Policy);
                }
                Ok(())
            })
            .map_err(|_| cgts::cblc::Error::Admission)?;
        publication.floor = observed;
        state.valid = true;
        Ok(())
    }
}
