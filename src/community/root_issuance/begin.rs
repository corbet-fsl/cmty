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
    /// Link an explicitly provisioned root purpose key to THIS root Community's
    /// original nonce store and Policy mutex. Source facades cannot construct a
    /// signer or select an alternative replay store.
    pub async fn root_board_issuer(
        &self,
        key: cpsd::IssuerKey,
        now: u64,
    ) -> Result<RootBoardIssuer<S::Challenges, R, P, K>>
    where
        S::Challenges: Clone,
    {
        if !self.root_board {
            return Err(Error::Scope);
        }
        RootBoardIssuer::new(
            self.root_issuance_store.clone(),
            key,
            self.policy.clone(),
            now,
        )
        .await
    }

    /// Begin original blind root issuance for an actual current source garden
    /// member. The host retains the original authenticated session through this
    /// operation, supplies its exclusive expiry and the direct live clock.
    /// Acquire root Policy, then source Policy, then the source member lease.
    pub async fn begin_root_board_issuance<T: ChallengeStore, Q: RngCore + CryptoRng>(
        &self,
        issuer: &RootBoardIssuer<T, R, P, K>,
        rng: &mut Q,
        session: &RootBoardSession<'_, impl Fn() -> u64>,
    ) -> Result<RootBoardChallenge> {
        if self.root_board || Arc::ptr_eq(&self.policy, &issuer.policy) {
            return Err(Error::Scope);
        }
        let mut time = LiveTime::new(&session.clock, 0)?;
        let mut root = issuer.policy.lock().await;
        let mut source = self.policy.lock().await;
        let mut lease = self
            .membership
            .role_until(session.authentication, session.valid_until)
            .await
            .map_err(member_error)?;
        source_role(&lease, &self.community)?;
        self.membership
            .check_role_action(&mut lease, "root_board_issue_begin")
            .await
            .map_err(member_error)?;
        let now = time.observe()?;
        if !lease.is_current(now) {
            return Err(Error::Time);
        }
        let snapshot = self.snapshot_locked(&source, now).await?;
        let settings_until = source
            .verified_settings(now)
            .await
            .map_err(policy_error)?
            .valid_until();
        let (descriptor, root_until) = issuer.current(&root, now).await?;
        let lifetime = self.config.read().map_err(policy_error)?.challenge_lifetime;
        // CPSD's context deadline is inclusive; every authority bound here is
        // exclusive. Never equate a context deadline with the lease's expiry.
        let until = lease
            .valid_until()
            .min(snapshot.valid_until)
            .min(snapshot.passport.valid_until)
            .min(settings_until)
            .min(root_until)
            .min(descriptor.expires_at());
        let deadline = now
            .checked_add(lifetime)
            .ok_or(Error::Time)?
            .min(until.checked_sub(1).ok_or(Error::Time)?);
        if deadline <= now {
            return Err(Error::Time);
        }
        let request = PresentationRequest::for_epoch(
            rng,
            self.community.clone(),
            snapshot.passport.epoch,
            snapshot.passport.gates.iter().cloned(),
            deadline,
            snapshot.passport.valid_until,
        )?;
        let context = cpsd::RootBoardIssuanceContext::new(rng, request, descriptor)?;
        let source_signature = source
            .sign_presentation_request(context.source_request(), now)
            .await
            .map_err(signing_error)?;
        let root_signature = root
            .sign_root_board_issuance_context(&context, now)
            .await
            .map_err(signing_error)?;
        // Only this fresh service-created context is ever registered. A lost
        // response expires anonymously; no retry API can re-register its nonce.
        cpsd::register_root_board_issuance(&issuer.store, &context).await?;
        self.membership
            .check_role_action(&mut lease, "root_board_issue_begin")
            .await
            .map_err(member_error)?;
        let checked_at = time.release(&lease, &context)?;
        Ok(RootBoardChallenge {
            context,
            source_signature,
            root_signature,
            source_policy: snapshot,
            checked_at,
        })
    }
}
