//! Original certificate owner composition with Policy-first lease ordering.
use super::*;

/// Original signed bytes and the actual completed membership check observation.
/// This result records one completed operation; it retains no live owner lease.
#[must_use]
pub struct PasskeyCertificate {
    bytes: Vec<u8>,
    checked_at: u64,
}
impl PasskeyCertificate {
    /// Original COSE bytes, unchanged by this ephemeral completion result.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual completion time of the retained original membership check.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Consume the result after carrying its completion floor to the next check.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
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
    /// Renew the current authenticated key's certificate, including recovery of
    /// an unknown delivery outcome after registration already committed.
    pub async fn passkey_certificate(
        &self,
        authentication: &ckyh::Authentication,
        now: u64,
    ) -> Result<PasskeyCertificate> {
        let mut policy = self.policy.lock().await;
        let mut registered = self
            .membership
            .passkey_certificate(authentication)
            .await
            .map_err(member_error)?;
        let certificate = policy
            .issue_passkey_certificate(registered.certificate(), now)
            .await
            .map_err(policy_error)?;
        let completed = self
            .membership
            .check_certificate(&mut registered)
            .await
            .map_err(member_error)?;
        if completed < now {
            return Err(Error::Policy);
        }
        policy
            .key_ring()
            .map_err(policy_error)?
            .verify(&certificate, csgn::Kind::Credential, completed)
            .map_err(policy_error)?;
        Ok(PasskeyCertificate {
            bytes: certificate,
            checked_at: completed,
        })
    }
}
