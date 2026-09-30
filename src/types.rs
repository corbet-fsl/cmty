//! Proof-level inputs and the versioned community credential payload.

use std::collections::{BTreeMap, BTreeSet};

use cpsd::{CommunityId, GateId};
use serde::{Deserialize, Serialize};

/// The only action that authorizes community credential issuance.
pub const ADMISSION_ACTION: &str = "community.admit";
/// Provider label for globally verified proof metadata, not a raw gate provider.
pub const PASSPORT_PROVIDER: &str = "cpsd";
/// Maximum lifetime for a new member, in seconds.
pub const NEW_MEMBER_LIFETIME: u64 = cplc::NEW_MEMBER_VALIDITY;
/// Maximum lifetime for an established member, in seconds.
pub const ESTABLISHED_MEMBER_LIFETIME: u64 = cplc::ESTABLISHED_MEMBER_VALIDITY;

/// Authenticated common-expiry passport policy from the global level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassportPolicy {
    /// Required global policy epoch, distinct from the community policy epoch.
    pub epoch: u64,
    /// Common passport/gate expiry authenticated from the issuer schedule.
    pub valid_until: u64,
    /// Gates the holder must disclose for admission.
    pub gates: BTreeSet<GateId>,
}

/// Effective state from the policy facade; never accept this from an HTTP client.
#[derive(Clone)]
pub struct PolicySnapshot {
    /// Resolved rulebook. Its community must be the canonical UTF-8 scope.
    pub rules: crbk::Snapshot,
    /// Current profile schema version.
    pub schema_version: u64,
    /// Authenticated global policy cohort.
    pub passport: PassportPolicy,
    /// Freshness deadline for these settings/schema, exclusive.
    pub valid_until: u64,
    /// Trusted community ring; issuer must equal the canonical community.
    pub signing_keys: csgn::KeyRing,
}

impl PolicySnapshot {
    pub(crate) fn unchanged(&self, other: &Self) -> bool {
        self.rules.community == other.rules.community
            && self.rules.revision == other.rules.revision
            && self.rules.policy_epoch == other.rules.policy_epoch
            && self.rules.content == other.rules.content
            && self.schema_version == other.schema_version
            && self.passport == other.passport
            && self.valid_until == other.valid_until
            && self.signing_keys.to_cbor() == other.signing_keys.to_cbor()
    }
}

/// A community gate recorded in the credential. Proof time is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialGate {
    /// Gate name.
    pub gate: String,
    /// Community-level provider name.
    pub provider: String,
    /// Exclusive expiry.
    pub valid_until: u64,
}

/// Verified view of the cplc payload plus protected COSE metadata.
/// This view is not the wire payload: cplc owns that format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    /// Verified view version (1), not a field in the cplc wire payload.
    pub version: u8,
    /// Canonical community, never a mutable display name.
    pub community: String,
    /// Community pseudonym; never a global holder identifier.
    pub member_id: String,
    /// Membership-owned handle.
    pub handle: String,
    /// Community proof metadata; global gate disclosures are not copied here.
    pub gates: Vec<CredentialGate>,
    /// Sealed field fingerprints only.
    pub pins: BTreeMap<String, [u8; 32]>,
    /// Authorized public device keys.
    pub devices: Vec<[u8; 32]>,
    /// Schema version.
    pub schema_version: u64,
    /// Community policy epoch.
    pub policy_epoch: u64,
    /// Issuance in unsigned Unix seconds; returned, never persisted by cmnt.
    pub issued: u64,
    /// Exclusive expiry.
    pub valid_until: u64,
    /// Active community COSE key thumbprint.
    pub key_id: Vec<u8>,
}

/// A successful issuance. This value must not be stored as a request log.
pub struct IssuedCredential {
    /// Authenticated credential claims.
    pub claims: CredentialClaims,
    /// Tagged Ed25519 COSE_Sign1 bytes.
    pub cose: Vec<u8>,
}

impl CredentialClaims {
    /// The canonical cplc JSON payload, excluding authenticated COSE headers.
    pub fn payload(&self) -> crate::Result<cplc::Credential> {
        Ok(cplc::Credential {
            community: self.community.clone(),
            member: self.member_id.clone(),
            handle: self.handle.clone(),
            schema_version: self
                .schema_version
                .try_into()
                .map_err(|_| crate::Error::Policy)?,
            policy_epoch: self.policy_epoch,
            gates: self
                .gates
                .iter()
                .map(|gate| cplc::CredentialGate {
                    gate: gate.gate.clone(),
                    provider: gate.provider.clone(),
                    valid_until: gate.valid_until,
                })
                .collect(),
            pins: self
                .pins
                .iter()
                .map(|(field, fingerprint)| cplc::Pin {
                    field: field.clone(),
                    fingerprint: *fingerprint,
                })
                .collect(),
            devices: self.devices.clone(),
        })
    }
}

/// Gate/rulebook refusal, or a signed credential.
pub enum Outcome {
    /// Resume the lobby with the rulebook's missing requirements.
    Missing(crbk::Decision),
    /// Unconditional legal veto; no authority/order data is exposed.
    Vetoed,
    /// Credential issued after admission was committed.
    Issued(Box<IssuedCredential>),
}

pub(crate) fn community_text(community: &CommunityId) -> crate::Result<&str> {
    let value = std::str::from_utf8(community.as_bytes()).map_err(|_| crate::Error::Scope)?;
    if value.contains('\0') || value.len() > csgn::MAX_ISSUER_LEN {
        return Err(crate::Error::Scope);
    }
    Ok(value)
}
