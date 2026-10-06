//! Pause only after the original nonce store commits; every result is unchanged.
use super::*;
use cpsd::ChallengeStore as _;
use crbk::Storage as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Pause {
    armed: AtomicBool,
    reached: Notify,
    resume: Notify,
}

#[derive(Clone)]
struct PausingStore {
    inner: cpsd::storage::libsql::LibsqlStore,
    pause: Arc<Pause>,
}

impl cmty::storage::Storage for PausingStore {
    type Challenges = Self;

    fn challenges(&self) -> Self {
        self.clone()
    }
}

impl cpsd::ChallengeStore for PausingStore {
    fn community(&self) -> &cpsd::CommunityId {
        self.inner.community()
    }

    async fn reserve(
        &self,
        record: cpsd::storage::ChallengeRecord,
    ) -> std::result::Result<bool, cpsd::Error> {
        self.inner.reserve(record).await
    }

    async fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: u64,
    ) -> std::result::Result<bool, cpsd::Error> {
        self.inner.matches(nonce, binding, now).await
    }

    async fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: u64,
    ) -> std::result::Result<bool, cpsd::Error> {
        let consumed = self.inner.consume(nonce, binding, now).await?;
        if consumed && self.pause.armed.swap(false, Ordering::SeqCst) {
            self.pause.reached.notify_one();
            self.pause.resume.notified().await;
        }
        Ok(consumed)
    }

    async fn prune(&self, now: u64) -> std::result::Result<u64, cpsd::Error> {
        self.inner.prune(now).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_change_after_real_nonce_commit_fences_the_first_admission_snapshot() {
    let pause = Arc::new(Pause::default());
    let mut f = fixture_with(EXPIRY, EXPIRY, |db| PausingStore {
        inner: cpsd::storage::libsql::LibsqlStore::new(db, scope(), 32).unwrap(),
        pause: pause.clone(),
    })
    .await;
    let (challenge, proof) = f.proof().await;
    pause.armed.store(true, Ordering::SeqCst);
    let attempt = f.engine.finish(
        &mut f.rng,
        &challenge,
        &proof,
        Admission {
            authentication: &f.auth.authentication,
            devices: &f.devices,
            lease: crgs::YearMonth::new(2027, 9).unwrap(),
        },
        NOW,
    );
    let change = async {
        pause.reached.notified().await;
        f.engine
            .policy()
            .lock()
            .await
            .set_schema(schema(4))
            .await
            .unwrap();
        pause.resume.notify_one();
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(attempt, change)
    })
    .await
    .expect("real storage/policy interleaving did not complete");
    assert!(matches!(result, Err(Error::Policy)));
    let verifier = cpsd::Verifier::new(
        cpsd::storage::libsql::LibsqlStore::new(&f.db, scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
    )
    .unwrap();
    assert!(
        verifier
            .verify(&mut f.rng, challenge.request(), &proof, 7, NOW)
            .await
            .is_err()
    );
}

#[derive(Clone)]
struct PausingRules {
    inner: Rules,
    enrolments: cnrl::LibsqlStorage,
    pause: Arc<Pause>,
}

impl crbk::Storage for PausingRules {
    async fn load(
        &self,
        community: &str,
        selection: crbk::Selection,
    ) -> crbk::Result<Option<crbk::Revision>> {
        if self.pause.armed.load(Ordering::SeqCst)
            && cnrl::Storage::load(&self.enrolments, USER)
                .await
                .expect("original enrolment store")
                .is_some_and(|row| row.state() == State::Admitted)
            && self.pause.armed.swap(false, Ordering::SeqCst)
        {
            self.pause.reached.notify_one();
            self.pause.resume.notified().await;
        }
        self.inner.load(community, selection).await
    }

    async fn append(
        &self,
        community: &str,
        expected: Option<u64>,
        change: crbk::Change,
    ) -> crbk::Result<crbk::Revision> {
        self.inner.append(community, expected, change).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn real_rulebook_commit_after_membership_admission_fences_the_final_snapshot() {
    let pause = Arc::new(Pause::default());
    let mut f = fixture_with_rule_store(
        EXPIRY,
        EXPIRY,
        |db| cmty::storage::LibsqlStorage::new(db, scope(), 32).unwrap(),
        None,
        7,
        |db| PausingRules {
            inner: cmty::adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone())),
            enrolments: cnrl::LibsqlStorage::new(db, "example").unwrap(),
            pause: pause.clone(),
        },
    )
    .await;
    let original = f.engine.snapshot(NOW).await.unwrap();
    let (challenge, proof) = f.proof().await;
    pause.armed.store(true, Ordering::SeqCst);
    let attempt = f.engine.finish(
        &mut f.rng,
        &challenge,
        &proof,
        Admission {
            authentication: &f.auth.authentication,
            devices: &f.devices,
            lease: crgs::YearMonth::new(2027, 9).unwrap(),
        },
        NOW,
    );
    let change = async {
        pause.reached.notified().await;
        // A second real writer appends through the original Rulebook owner API.
        // No loaded value, membership result or signed credential is replaced.
        let revision = crbk::LibsqlStore::new(f.db.clone())
            .append(
                "example",
                Some(original.rules.revision),
                crbk::Change {
                    rulebook: f.rules.clone(),
                    announced_at: NOW as i64,
                    effective_at: NOW as i64,
                    notice_seconds: 0,
                    policy_epoch: original.rules.policy_epoch + 1,
                },
            )
            .await
            .unwrap();
        assert_eq!(revision.revision, original.rules.revision + 1);
        pause.resume.notify_one();
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(attempt, change)
    })
    .await
    .expect("real rulebook/membership interleaving did not complete");
    assert!(matches!(result, Err(Error::Policy)));
    assert_eq!(
        cnrl::Storage::load(&cnrl::LibsqlStorage::new(&f.db, "example").unwrap(), USER)
            .await
            .unwrap()
            .unwrap()
            .state(),
        State::Admitted
    );
    let verifier = cpsd::Verifier::new(
        cpsd::storage::libsql::LibsqlStore::new(&f.db, scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
    )
    .unwrap();
    assert!(
        verifier
            .verify(&mut f.rng, challenge.request(), &proof, 7, NOW)
            .await
            .is_err()
    );
}
