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
    /// Issue only while the actual source role, passkey, legal standing, Policy
    /// and original host session remain current. The host must retain its real
    /// session owner guard, not merely a copied session expiry, through this
    /// call and its synchronous response publication. No source role is stored
    /// or returned with the original blind credential.
    pub async fn finish_root_board_issuance<T: ChallengeStore, Q: RngCore + CryptoRng>(
        &self,
        issuer: &RootBoardIssuer<T, R, P, K>,
        rng: &mut Q,
        session: &RootBoardSession<'_, impl Fn() -> u64>,
        challenge: &RootBoardChallenge,
        request: &cpsd::RootBoardIssuanceRequest,
    ) -> Result<cpsd::BlindRootBoardCredential> {
        if self.root_board
            || Arc::ptr_eq(&self.policy, &issuer.policy)
            || challenge.context.source_request().community() != &self.community
        {
            return Err(Error::Scope);
        }
        let mut time = LiveTime::new(&session.clock, challenge.checked_at)?;
        let root = issuer.policy.lock().await;
        let mut source = self.policy.lock().await;
        let mut lease = self
            .membership
            .role_until(session.authentication, session.valid_until)
            .await
            .map_err(member_error)?;
        source_role(&lease, &self.community)?;
        let now = self
            .root_issuance_current(issuer, &root, &mut source, challenge, &mut lease, &mut time)
            .await?;
        let verified = self
            .verifier
            .verify_root_board_issuance(&issuer.store, &challenge.context, request, now)
            .await?;
        if verified.source_community().as_bytes() != lease.community().as_bytes()
            || verified.source_pseudonym().to_hex() != lease.member()
        {
            return Err(Error::Membership);
        }
        let now = self
            .root_issuance_current(issuer, &root, &mut source, challenge, &mut lease, &mut time)
            .await?;
        let consumed = cpsd::consume_root_board_issuance(&issuer.store, verified, now).await?;
        // The original owner contract explicitly requires a fresh source check
        // AFTER nonce consumption. Cancellation/refusal here burns the nonce.
        let now = self
            .root_issuance_current(issuer, &root, &mut source, challenge, &mut lease, &mut time)
            .await?;
        // The source DB barrier is deliberately acquired only AFTER root nonce
        // consumption: both scopes may use one physical database. Genuine SDK
        // key/legal writers cannot change the final authority bundle mid-sign.
        let answer = self
            .membership
            .with_current_role_action(&mut lease, "root_board_issue_finish", |checked_at| {
                let direct = time.observe().map_err(|_| cmbr::Error::Transition)?;
                if direct != checked_at || direct < now || direct > challenge.context.deadline() {
                    return Err(cmbr::Error::Transition);
                }
                consumed
                    .issue(rng, &issuer.key, challenge.context.root(), direct)
                    .map_err(|_| cmbr::Error::Unavailable)
            })
            .await
            .map_err(member_error)?;
        if time.release(&lease, &challenge.context)? != lease.checked_at() {
            // A scheduled restriction can activate without another writer.
            // Preserve the final read/sign barrier's same-second authority
            // through this synchronous release; the consumed nonce stays spent.
            return Err(Error::Time);
        }
        // No await between the final authority cut and returning these bytes.
        Ok(answer)
    }

    async fn root_issuance_current<T: ChallengeStore>(
        &self,
        issuer: &RootBoardIssuer<T, R, P, K>,
        root: &cplc::Policy<R, P, K>,
        source: &mut cplc::Policy<R, P, K>,
        challenge: &RootBoardChallenge,
        lease: &mut cmbr::RoleLease,
        time: &mut LiveTime<'_, impl Fn() -> u64>,
    ) -> Result<u64> {
        let now = time.release(lease, &challenge.context)?;
        let current = self.snapshot_locked(source, now).await?;
        ensure_unchanged(&challenge.source_policy, &current)?;
        let settings_until = source
            .verified_settings(now)
            .await
            .map_err(policy_error)?
            .valid_until();
        let (descriptor, until) = issuer.current(root, now).await?;
        if &descriptor != challenge.context.root()
            || challenge.context.deadline() >= until.min(settings_until)
        {
            return Err(Error::Policy);
        }
        self.membership
            .check_role(lease)
            .await
            .map_err(member_error)?;
        source_role(lease, &self.community)?;
        time.release(lease, &challenge.context)
    }
}
