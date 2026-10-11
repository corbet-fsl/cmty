//! Original joint root-board admission over the real passport and Policy owners.
use super::*;

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
    /// Compose the reserved root community with mandatory same-holder joint admission.
    pub fn new_root_board(
        storage: S,
        issuer_keys: Vec<IssuerPublicKey>,
        parts: Parts<M, L, C, G, A, R, P, K>,
        config: Config,
    ) -> Result<Self> {
        Self::new_selected(storage, issuer_keys, parts, config, true)
    }

    async fn begin_selected<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        now: u64,
    ) -> Result<Challenge> {
        self.flush_revocations(now).await?;
        let mut signer = self.policy.lock().await;
        let policy = self.snapshot_locked(&signer, now).await?;
        let lifetime = self.config.read().map_err(policy_error)?.challenge_lifetime;
        let mut deadline = now
            .checked_add(lifetime)
            .ok_or(Error::Time)?
            .min(policy.passport.valid_until - 1)
            .min(policy.valid_until - 1);
        if deadline <= now {
            return Err(Error::Time);
        }
        let descriptor = if self.root_board {
            let (descriptor, until) = signer
                .root_board_descriptor(now)
                .await
                .map_err(policy_error)?
                .ok_or(Error::Policy)?;
            deadline = deadline.min(until.checked_sub(1).ok_or(Error::Time)?);
            Some(descriptor)
        } else {
            None
        };
        if deadline <= now {
            return Err(Error::Time);
        }
        let (request, root_board, signed_request) = if let Some(descriptor) = descriptor {
            let global = PresentationRequest::for_epoch(
                rng,
                self.community.clone(),
                policy.passport.epoch,
                policy.passport.gates.iter().cloned(),
                deadline,
                policy.passport.valid_until,
            )?;
            let joint = self
                .verifier
                .register_root_board_request(cpsd::RootBoardRequest::new(global, descriptor)?)
                .await?;
            let signed = signer
                .sign_root_board_request(&joint, now)
                .await
                .map_err(signing_error)?;
            (joint.global_request().clone(), Some(joint), signed)
        } else {
            let request = self
                .verifier
                .request_for_epoch(
                    rng,
                    policy.passport.epoch,
                    policy.passport.gates.iter().cloned(),
                    deadline,
                    policy.passport.valid_until,
                )
                .await?;
            let signed_request = signer
                .sign_presentation_request(&request, now)
                .await
                .map_err(signing_error)?;
            (request, None, signed_request)
        };
        Ok(Challenge {
            request,
            root_board,
            signed_request,
            policy,
            not_before: now,
        })
    }

    /// Verify and consume the exact retained joint challenge under the current descriptor.
    pub async fn verify_root_board(
        &self,
        challenge: &Challenge,
        presentation: &cpsd::RootBoardPresentation,
        now: u64,
    ) -> Result<VerifiedPassport> {
        check_time(now)?;
        let request = challenge.root_board.as_ref().ok_or(Error::Passport)?;
        if !self.root_board
            || now < challenge.not_before
            || request.global_request().community() != &self.community
        {
            return Err(Error::Passport);
        }
        let signer = self.policy.lock().await;
        let policy = self.snapshot_locked(&signer, now).await?;
        let (descriptor, _) = signer
            .root_board_descriptor(now)
            .await
            .map_err(policy_error)?
            .ok_or(Error::Policy)?;
        if !policy.unchanged(&challenge.policy) || &descriptor != request.root() {
            return Err(Error::Policy);
        }
        let witness = cgts::verify_root_board_passport(
            &self.verifier,
            request,
            presentation,
            policy.passport.epoch,
            now,
        )
        .await
        .map_err(|_| Error::Passport)?;
        Ok(VerifiedPassport {
            member_id: witness.pseudonym().to_hex(),
            witness,
            community: self.community.clone(),
            policy,
            verified_at: now,
            root_board: Some(descriptor),
        })
    }

    async fn passport_current(
        &self,
        passport: &VerifiedPassport,
        policy: &cplc::Policy<R, P, K>,
        now: u64,
    ) -> Result<()> {
        if !passport
            .policy
            .unchanged(&self.snapshot_locked(policy, now).await?)
        {
            return Err(Error::Policy);
        }
        if self.root_board {
            let (current, _) = policy
                .root_board_descriptor(now)
                .await
                .map_err(policy_error)?
                .ok_or(Error::Policy)?;
            if passport.root_board.as_ref() != Some(&current) {
                return Err(Error::Policy);
            }
        } else if passport.root_board.is_some() {
            return Err(Error::Passport);
        }
        Ok(())
    }

    /// Issue ordinary root membership only after the mandatory genuine joint proof.
    pub async fn finish_root_board_with(
        &self,
        challenge: &Challenge,
        presentation: &cpsd::RootBoardPresentation,
        admission: Admission<'_>,
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        let passport = self.verify_root_board(challenge, presentation, now).await?;
        self.finish_verified(passport, (admission, None), now, checks)
            .await
    }
}
