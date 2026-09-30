//! Community admission: passport verification, membership, gates and policy.
//!
//! The service owns authentication, clocks, rate limits, canonical community
//! routing and authenticated policy/key distribution. See `docs/CONTRACT.md`.
#![forbid(unsafe_code)]

pub mod adapters;
mod community;
pub mod storage;
mod types;

pub use community::{Admission, Challenge, Community, Config, Parts, VerifiedPassport};
pub use types::*;
/// Exact protocol types of the composed facades.
pub use {cgts, cmbr, cplc};

/// Redacted integration errors; no upstream request/proof/subject is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A component was bound to another community or an invalid scope.
    #[error("invalid community scope")]
    Scope,
    /// Invalid authoritative time or challenge lifetime.
    #[error("invalid time or lifetime")]
    Time,
    /// Passport, epoch, challenge or replay check failed.
    #[error("passport verification or challenge failed")]
    Passport,
    /// Challenge persistence/capacity failed.
    #[error("challenge storage unavailable")]
    Storage,
    /// The trusted membership facade refused the operation.
    #[error("membership unavailable or changed")]
    Membership,
    /// A gate failed or returned invalid metadata.
    #[error("community gate unavailable or invalid")]
    Gate,
    /// Invalid/expired policy or policy changed during this attempt.
    #[error("policy unavailable or changed")]
    Policy,
    /// Signing failed or returned inconsistent authenticated claims.
    #[error("credential signing failed")]
    Signing,
}

impl From<cpsd::Error> for Error {
    fn from(error: cpsd::Error) -> Self {
        match error {
            cpsd::Error::Storage | cpsd::Error::StorageCapacity => Self::Storage,
            _ => Self::Passport,
        }
    }
}

/// Result with a redacted community error.
pub type Result<T> = std::result::Result<T, Error>;
