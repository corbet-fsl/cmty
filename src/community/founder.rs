//! Original FounderAdmin entitlement accompanies complete genuine admission.
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
    /// Verify the same original passport and all configured gates, then redeem
    /// the exact original FounderAdmin voucher through Membership's one writer.
    /// The voucher grants no passport, gate, device or session authority.
    pub async fn finish_founder_admin_with<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        admission: Admission<'_>,
        invitation: &[u8],
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        if admission.creation.is_some() {
            return Err(Error::Membership);
        }
        let passport = self.verify(rng, challenge, presentation, now).await?;
        self.finish_verified_entitled(passport, (admission, None), Some(invitation), now, checks)
            .await
    }

    /// The same FounderAdmin admission with Policy's original native-account
    /// grant for one genuinely authorized device; no substitute grant is made.
    pub async fn finish_founder_admin_account_with<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        challenge: &Challenge,
        presentation: &Presentation,
        admission: AccountAdmission<'_>,
        invitation: &[u8],
        now: u64,
        checks: impl AsyncFnOnce(
            &cgts::Gatekeeper<G, A>,
            cgts::Context<'_>,
        ) -> cgts::Result<Vec<cgts::CheckedGate>>,
    ) -> Result<Outcome> {
        if admission.membership.creation.is_some() {
            return Err(Error::Membership);
        }
        let passport = self.verify(rng, challenge, presentation, now).await?;
        self.finish_verified_entitled(
            passport,
            (admission.membership, Some(admission.device)),
            Some(invitation),
            now,
            checks,
        )
        .await
    }
}
