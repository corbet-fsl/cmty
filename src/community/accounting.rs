//! Original accounting composition under current Policy and member authority.
use super::*;
use cgts::{AccountServiceRequest, AccountServiceResponse};

/// Admission requesting Policy's original account grant for one already
/// authorized device. Global cohort metadata always comes from Community.
pub struct AccountAdmission<'a> {
    /// The same authenticated membership and gate inputs as normal admission.
    pub membership: Admission<'a>,
    /// One current device key; Policy refuses keys outside member authority.
    pub device: [u8; 32],
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
