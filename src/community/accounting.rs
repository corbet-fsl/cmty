//! Original accounting composition under current Policy and member authority.
use super::*;
use cgts::{AccountServiceRequest, AccountServiceResponse};
mod authority;
mod enrollment;
mod publication;
mod settlement;
pub use authority::AccountSession;
mod lifecycle;
mod pin_change;
mod succession;
pub use pin_change::PinChange;

/// Admission requesting Policy's original account grant for one already
/// authorized device. Global cohort metadata always comes from Community.
pub struct AccountAdmission<'a> {
    /// The same authenticated membership and gate inputs as normal admission.
    pub membership: Admission<'a>,
    /// One current device key; Policy refuses keys outside member authority.
    pub device: [u8; 32],
}

/// Common object returned only after the actual Policy/Beacon publication.
/// Host data; no serialized verifier verdict or member authority is exposed.
pub struct AccountPublication {
    /// Original native epoch descriptor and one common encrypted object.
    pub record: cgts::cblc::accounting_ledger::record_epoch::RecordEpochPublication,
    /// The exact refreshed signed original publication feed.
    pub feed: std::sync::Arc<cplc::cbcn::Feed>,
}

impl<S, M, L, C, G, A, R, P, K> Community<S, M, L, C, G, A, R, P, K>
where
    S: Storage,
    M: cmbr::Storage + Send + Sync + 'static,
    L: clbs::Verifier + Send + Sync + 'static,
    C: clbs::Clock + Send + Sync + 'static,
    G: cgts::Storage,
    A: cgts::LegalVeto,
    R: crbk::Storage,
    P: cplc::Storage,
    K: csgn::Store,
{
    /// Install the original single Balance service with its trusted live
    /// service clock, never a frozen request timestamp.
    pub async fn with_account_service<V, Clock>(
        mut self,
        service: cgts::cblc::accounting_service::AccountService<V, Clock>,
    ) -> Result<Self>
    where
        V: cgts::cblc::accounting::AccountProofVerifier + Send + 'static,
        Clock: Fn() -> u64 + Send + 'static,
    {
        self.gates =
            self.gates
                .with_account_service(service)
                .await
                .map_err(|error| match error {
                    cgts::Error::Scope => Error::Scope,
                    cgts::Error::Storage => Error::Storage,
                    _ => Error::Gate,
                })?;
        Ok(self)
    }

    /// Install the actual native service with its same proof cancellation and
    /// join owner. The host retains `account_shutdown` outside Community locks.
    pub async fn with_native_account_service<Clock>(
        mut self,
        service: cgts::cblc::accounting_service::AccountService<
            cgts::cblc::accounting_service::NativeAccountVerifier,
            Clock,
        >,
    ) -> Result<Self>
    where
        Clock: Fn() -> u64 + Send + 'static,
    {
        self.gates = self
            .gates
            .with_native_account_service(service)
            .await
            .map_err(|error| match error {
                cgts::Error::Scope => Error::Scope,
                cgts::Error::Storage => Error::Storage,
                _ => Error::Gate,
            })?;
        Ok(self)
    }

    /// Host-only teardown handle; retain before handling requests and use it
    /// without acquiring a Community, Policy or member lock during shutdown.
    pub fn account_shutdown(&self) -> Result<cgts::AccountShutdown> {
        self.gates.account_shutdown().map_err(|error| match error {
            cgts::Error::Disabled => Error::AccountUnavailable,
            _ => Error::Storage,
        })
    }

    /// Forward to the one configured Gatekeeping account service using current
    /// member authority, independently of every identity in the request body.
    /// The Balance service retains the live clock used during proof verification.
    pub async fn account(
        &self,
        auth: std::sync::Arc<ckyh::Authentication>,
        request: AccountServiceRequest,
        now: u64,
        session: std::sync::Arc<dyn AccountSession>,
    ) -> Result<AccountServiceResponse>
    where
        R: Send + 'static,
        P: Send + 'static,
        K: Send + 'static,
    {
        let grant = match &request {
            AccountServiceRequest::RegisterRecordRecipient { grant, .. }
            | AccountServiceRequest::Apply { grant, .. }
            | AccountServiceRequest::ApplyExtended { grant, .. }
            | AccountServiceRequest::Obligations { grant, .. }
            | AccountServiceRequest::Status { grant, .. } => grant,
        };
        let prepared = self
            .prepare_account_member(auth, grant, now, session, false)
            .await?;
        let context = cgts::Context {
            snapshot: &prepared.settings,
            subject: &prepared.subject,
            action: "community.account",
            now: now as i64,
        };
        self.gates
            .account_authorized(context, prepared.pseudonym, request, prepared.authority)
            .await
            .map_err(|error| match error {
                cgts::Error::Disabled => Error::AccountUnavailable,
                cgts::Error::Storage | cgts::Error::Account(_) => Error::Reconcile,
                _ => Error::Gate,
            })
    }

    /// Publish the configured original epoch on the same native account owner,
    /// then sign its exact actual material through Policy and Beacon. Only a
    /// trusted application-selected catalogue key and live host clock enter.
    pub async fn publish_account_record(
        &self,
        period_key: &str,
        clock: impl Fn() -> u64 + Send + Sync,
    ) -> Result<AccountPublication>
    where
        R: Send + 'static,
        P: Send + 'static,
        K: Send + 'static,
    {
        let (record, feed) = self
            .publish_account(period_key, clock, PublicationKind::Record)
            .await?;
        Ok(AccountPublication {
            record: record.ok_or(Error::Reconcile)?,
            feed,
        })
    }

    /// Publish actual native bootstrap material through Policy/Beacon. An absent
    /// record epoch remains absent; this cannot authorize mandatory Forum G2.
    pub async fn publish_account_material(
        &self,
        period_key: &str,
        clock: impl Fn() -> u64 + Send + Sync,
    ) -> Result<std::sync::Arc<cplc::cbcn::Feed>>
    where
        R: Send + 'static,
        P: Send + 'static,
        K: Send + 'static,
    {
        let (_, feed) = self
            .publish_account(period_key, clock, PublicationKind::Material)
            .await?;
        Ok(feed)
    }

    async fn publish_account(
        &self,
        period_key: &str,
        clock: impl Fn() -> u64 + Send + Sync,
        kind: PublicationKind,
    ) -> Result<(
        Option<cgts::cblc::accounting_ledger::record_epoch::RecordEpochPublication>,
        std::sync::Arc<cplc::cbcn::Feed>,
    )>
    where
        R: Send + 'static,
        P: Send + 'static,
        K: Send + 'static,
    {
        let mut floor = 0;
        let now = host_time(&clock, &mut floor)?;
        self.flush_revocations(now).await?;
        host_time(&clock, &mut floor)?;
        let policy = self.policy.clone().lock_owned().await;
        let now = host_time(&clock, &mut floor)?;
        let snapshot = self.snapshot_locked(&policy, now).await?;
        let now = host_time(&clock, &mut floor)?;
        let period = policy
            .record_epoch_settings(period_key, now)
            .await
            .map_err(policy_error)?;
        let now = host_time(&clock, &mut floor)?;
        let version = policy.balance_version(now).await.map_err(policy_error)?;
        let now = host_time(&clock, &mut floor)?;
        ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
        host_time(&clock, &mut floor)?;
        let (response, policy) = self
            .gates
            .account_host(
                match kind {
                    PublicationKind::Record => cgts::HostRequest::PublishRecord {
                        revision: version.revision,
                        policy_epoch: version.epoch,
                        period_seconds: period.period_seconds,
                    },
                    PublicationKind::Material => cgts::HostRequest::VerifierMaterial {
                        revision: version.revision,
                        policy_epoch: version.epoch,
                    },
                },
                policy,
            )
            .await
            .map_err(host_error)?;
        let (publication, material) = match (kind, response) {
            (
                PublicationKind::Record,
                cgts::HostResponse::Record {
                    publication,
                    material,
                },
            ) => (Some(publication), material),
            (PublicationKind::Material, cgts::HostResponse::VerifierMaterial(material)) => {
                (None, material)
            }
            _ => return Err(Error::Reconcile),
        };
        self.complete_account_publication(
            publication::PublicationState {
                policy,
                snapshot,
                period_key: period_key.to_owned(),
                period_seconds: period.period_seconds,
                version,
                floor,
            },
            (publication, material),
            &clock,
        )
        .await
    }

    /// Perform the same real admission and also project Policy's signed account
    /// grant from its current credential decision. No detached issuer or caller
    /// supplied global cohort is accepted. The configured Balance publication
    /// and selected device must be current, or no credential/grant is returned.
    pub async fn finish_account_with<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        admission: AccountAdmission<'_>,
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        self.finish_selected(
            rng,
            challenge,
            presentation,
            (admission.membership, Some(admission.device)),
            now,
            checks,
        )
        .await
    }
}

#[derive(Clone, Copy)]
enum PublicationKind {
    Record,
    Material,
}

fn host_time(clock: &impl Fn() -> u64, floor: &mut u64) -> Result<u64> {
    let now = clock();
    check_time(now)?;
    if now < *floor {
        return Err(Error::Time);
    }
    *floor = now;
    Ok(now)
}
fn host_error(error: cgts::Error) -> Error {
    match error {
        cgts::Error::Disabled => Error::AccountUnavailable,
        _ => Error::Reconcile,
    }
}
