//! Original accounting composition under current Policy and member authority.
use super::*;
use cgts::{AccountServiceRequest, AccountServiceResponse};
mod lifecycle;

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
        auth: &ckyh::Authentication,
        request: AccountServiceRequest,
        now: u64,
    ) -> Result<AccountServiceResponse>
    where
        R: Send + 'static,
        P: Send + 'static,
        K: Send + 'static,
    {
        check_time(now)?;
        self.flush_revocations(now).await?;
        let mut policy = self.policy.clone().lock_owned().await;
        let configuration = self.snapshot_locked(&policy, now).await?;
        let snapshot = policy.verified_settings(now).await.map_err(policy_error)?;
        let row = self.membership.resume(auth).await.map_err(member_error)?;
        let (facts, lease) =
            cplc::MembershipSource::membership(&self.membership, row.subject(), now)
                .await
                .map_err(|_| Error::Membership)?;
        // Revalidate the exact passkey after acquiring the member queue. This
        // read does not acquire a second lease or manufacture a credential.
        let current = self.membership.resume(auth).await.map_err(member_error)?;
        if current.subject() != facts.member
            || facts.community != community_text(&self.community)?
            || facts.state != crbk::MembershipState::Admitted
            || facts.lease_end <= now
        {
            return Err(Error::Membership);
        }
        let bytes = data_encoding::HEXLOWER
            .decode(current.subject().as_bytes())
            .map_err(|_| Error::Membership)?;
        let pseudonym = cpsd::Pseudonym::from_bytes(&bytes).map_err(|_| Error::Membership)?;
        let grant = match &request {
            AccountServiceRequest::RegisterRecordRecipient { grant, .. }
            | AccountServiceRequest::Apply { grant, .. }
            | AccountServiceRequest::ApplyExtended { grant, .. }
            | AccountServiceRequest::Obligations { grant, .. }
            | AccountServiceRequest::Status { grant, .. } => grant,
        };
        let device: [u8; 32] = data_encoding::BASE64URL_NOPAD
            .decode(grant.chat_public_key.as_bytes())
            .map_err(|_| Error::Membership)?
            .try_into()
            .map_err(|_| Error::Membership)?;
        if grant.community_id != facts.community
            || grant.pseudonym != current.subject()
            || grant.policy_epoch != snapshot.settings().policy_epoch
            || grant.passport_policy_digest
                != data_encoding::BASE64URL_NOPAD.encode(&configuration.passport.digest())
            || !facts.authorized_devices.contains(&device)
            || grant.issued_at > now
            || grant.expires_at <= now
            || grant.expires_at > facts.lease_end
            || grant.expires_at > snapshot.valid_until()
            || grant.expires_at > configuration.valid_until
            || grant.expires_at > configuration.passport.valid_until
        {
            return Err(Error::Membership);
        }
        let context = cgts::Context {
            snapshot: snapshot.settings(),
            subject: current.subject(),
            action: "community.account",
            now: now as i64,
        };
        self.gates
            .account(context, pseudonym, request, (lease, policy))
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
        let mut policy = self.policy.clone().lock_owned().await;
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
        let (response, mut policy) = self
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
        async {
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
            let now = host_time(&clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(&clock, &mut floor)?;
            let current_period = policy
                .record_epoch_settings(period_key, now)
                .await
                .map_err(policy_error)?;
            let now = host_time(&clock, &mut floor)?;
            let current_version = policy.balance_version(now).await.map_err(policy_error)?;
            let now = host_time(&clock, &mut floor)?;
            if current_period.period_seconds != period.period_seconds
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
                if epoch.expires_at.checked_sub(epoch.starts_at) != Some(period.period_seconds) {
                    return Err(Error::Reconcile);
                }
                epoch.check_time(now).map_err(|_| Error::Reconcile)?;
                epoch.expires_at
            } else {
                material.policy.account.policy_valid_until
            };
            let material_deadline = material.policy.account.policy_valid_until;
            let balance = policy
                .publish_balance(material, now)
                .await
                .map_err(|_| Error::Reconcile)?;
            let now = host_time(&clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(&clock, &mut floor)?;
            let feed = policy
                .refresh_trust(now)
                .await
                .map_err(|_| Error::Reconcile)?;
            let now = host_time(&clock, &mut floor)?;
            ensure_unchanged(&snapshot, &self.snapshot_locked(&policy, now).await?)?;
            let now = host_time(&clock, &mut floor)?;
            let final_period = policy
                .record_epoch_settings(period_key, now)
                .await
                .map_err(policy_error)?;
            let now = host_time(&clock, &mut floor)?;
            if final_period.period_seconds != period.period_seconds
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
                .min(epoch_deadline)
                .min(signed.valid_until());
            if host_time(&clock, &mut floor)? >= deadline {
                return Err(Error::Reconcile);
            }
            Ok((publication, feed))
        }
        .await
        .map_err(|_| Error::Reconcile)
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
