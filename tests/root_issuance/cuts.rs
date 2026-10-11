//! Controls after the genuine root SQLite compare-and-consume has succeeded.
use super::*;
use cpsd::{ChallengeRecord, ChallengeStore, Timestamp};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use tokio::sync::Notify;

pub const NORMAL: u8 = 0;
pub const PAUSE: u8 = 1;
pub const EXPIRE: u8 = 2;
pub const ROLLBACK: u8 = 3;

#[derive(Default)]
pub struct Cut {
    pub mode: AtomicU8,
    pub consumed: AtomicUsize,
    pub clock_samples: AtomicUsize,
    pub direct_samples: AtomicUsize,
    pub advance_at: AtomicUsize,
    pub after_time: AtomicI64,
    pub entered: Notify,
    pub resume: Notify,
}

#[derive(Clone)]
pub struct CutStorage {
    pub inner: cmty::storage::LibsqlStorage,
    pub cut: Arc<Cut>,
}

impl cmty::storage::Storage for CutStorage {
    type Challenges = CutChallenges;
    fn challenges(&self) -> Self::Challenges {
        CutChallenges {
            inner: self.inner.challenges(),
            cut: self.cut.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CutChallenges {
    inner: cpsd::storage::libsql::LibsqlStore,
    cut: Arc<Cut>,
}

impl ChallengeStore for CutChallenges {
    fn community(&self) -> &CommunityId {
        self.inner.community()
    }
    async fn reserve(&self, record: ChallengeRecord) -> std::result::Result<bool, cpsd::Error> {
        self.inner.reserve(record).await
    }
    async fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> std::result::Result<bool, cpsd::Error> {
        self.inner.matches(nonce, binding, now).await
    }
    async fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> std::result::Result<bool, cpsd::Error> {
        let consumed = self.inner.consume(nonce, binding, now).await?;
        if consumed {
            self.cut.consumed.fetch_add(1, Ordering::SeqCst);
            if self.cut.mode.load(Ordering::SeqCst) == PAUSE {
                self.cut.entered.notify_one();
                self.cut.resume.notified().await;
            }
        }
        Ok(consumed)
    }
    async fn prune(&self, now: Timestamp) -> std::result::Result<u64, cpsd::Error> {
        self.inner.prune(now).await
    }
}

/// Read the same fixture clock used by actual Membership. Changes model elapsed
/// time after a completed storage await, never a fabricated storage verdict.
pub fn now(clock: &Clock, cut: &Cut) -> u64 {
    let direct = cut.direct_samples.fetch_add(1, Ordering::SeqCst) + 1;
    if direct == cut.advance_at.load(Ordering::SeqCst) {
        clock.0.store((NOW + 1) as i64, Ordering::SeqCst);
    }
    if cut.consumed.load(Ordering::SeqCst) > 0 {
        match cut.mode.load(Ordering::SeqCst) {
            EXPIRE => clock
                .0
                .store(cut.after_time.load(Ordering::SeqCst), Ordering::SeqCst),
            ROLLBACK => {
                let sample = cut.clock_samples.fetch_add(1, Ordering::SeqCst);
                clock.0.store(
                    (if sample == 0 { NOW + 20 } else { NOW + 15 }) as i64,
                    Ordering::SeqCst,
                );
            }
            _ => (),
        }
    }
    clock.0.load(Ordering::SeqCst) as u64
}
