//! Storage composition: all challenge execution belongs to `cpsd` and `crlt`.

use crate::Result;
use cpsd::{ChallengeStore, CommunityId};

/// Community storage capability. Implementations supply shared, atomic challenge
/// state; constructing a verifier must never create an independent replay cache.
pub trait Storage {
    /// Leaf implementation of single-use challenge storage.
    type Challenges: ChallengeStore;

    /// Obtain a handle sharing the existing scope and outstanding challenges.
    fn challenges(&self) -> Self::Challenges;
}

/// Volatile storage for tests and single-process development. Clones share state.
#[derive(Clone)]
pub struct MemoryStorage(cpsd::MemoryStore);

impl MemoryStorage {
    /// Bind a canonical community and a positive pending-challenge capacity.
    pub fn new(community: CommunityId, capacity: usize) -> Result<Self> {
        Ok(Self(cpsd::MemoryStore::new(community, capacity)?))
    }
}

impl Storage for MemoryStorage {
    type Challenges = cpsd::MemoryStore;

    fn challenges(&self) -> Self::Challenges {
        self.0.clone()
    }
}

/// libSQL storage through the shared `crlt` database, never a second connection.
#[derive(Clone)]
pub struct LibsqlStorage(cpsd::storage::libsql::LibsqlStore);

impl LibsqlStorage {
    /// Use the service's database after applying [`SCHEMA`]. The service deploys
    /// one physical database per community and owns migration numbering.
    pub fn new(db: &crlt::Db, community: CommunityId, capacity: usize) -> Result<Self> {
        Ok(Self(cpsd::storage::libsql::LibsqlStore::new(
            db, community, capacity,
        )?))
    }

    /// Exercise every leaf query plan with real `EXPLAIN QUERY PLAN`.
    pub async fn check_indexes(&self) -> Result<()> {
        Ok(self.0.check_indexes().await?)
    }
}

impl Storage for LibsqlStorage {
    type Challenges = cpsd::storage::libsql::LibsqlStore;

    fn challenges(&self) -> Self::Challenges {
        self.0.clone()
    }
}

/// Append once to the complete service migration history. No member IDs,
/// credentials, proofs, login dates or history are stored by this facade.
pub const SCHEMA: &str = cpsd::storage::libsql::SCHEMA;
