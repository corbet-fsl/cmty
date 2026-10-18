//! Actual Policy writer -> native daily owner -> original signed Balance/Beacon.
//! The untouched activation proof initializes only this empty native owner;
//! these tests do not claim a member account or a changed-inbox R2 opening.
use super::*;
use cmty::cgts::cblc::{
    settlement::{SettlementConfig, SettlementIssuer},
    storage::{AccountStorage, MemoryStore},
};
use cplc::Storage as _;
use cpsd::rand::SeedableRng;
use openssl::rsa::Rsa;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use zeroize::Zeroizing;
#[path = "settlement/native.rs"]
mod native;

const REALM: &str = "community-example";
const AT: u64 = 114;
const PERIOD_KEY: &str = "record/window";
const QUOTA_KEY: &str = "outcomes/allowance";

type Host = Community<
    cmty::storage::LibsqlStorage,
    cmbr::LibsqlStorage,
    Authority,
    Clock,
    cgts::LibsqlStore,
    cgts::LegalGate<cgts::legal_storage::LibsqlStore, Authority>,
    cmty::adapters::SharedRulebook<crbk::LibsqlStore>,
    PublicationStore,
    csgn::LibsqlStore,
>;

// The actual SQL owner still performs every CAS. This bounded test boundary
// advances the SAME trusted clock only after the awaited real Balance write.
struct PublicationStore {
    inner: cplc::LibsqlStore,
    clock: Clock,
    late: Arc<AtomicBool>,
    advanced: Arc<AtomicBool>,
}
impl cplc::Storage for PublicationStore {
    fn community(&self) -> &str {
        self.inner.community()
    }
    async fn load(&self) -> cplc::Result<Option<cplc::StoredPolicy>> {
        self.inner.load().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<u64>,
        next: &cplc::StoredPolicy,
    ) -> cplc::Result<()> {
        self.inner.compare_exchange(expected, next).await?;
        let value = serde_json::to_value(next).unwrap();
        if value["balance"]["cose"].is_array() && self.late.swap(false, Ordering::SeqCst) {
            self.clock.0.store(200, Ordering::SeqCst);
            self.advanced.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    async fn compare_exchange_checked<G: crbk::CommitGuard>(
        &self,
        expected: Option<u64>,
        next: &cplc::StoredPolicy,
        guard: &mut G,
    ) -> cplc::Result<()> {
        self.inner
            .compare_exchange_checked(expected, next, guard)
            .await
    }
}

struct Fixture {
    host: Host,
    clock: Clock,
    store: MemoryStore,
    late: Arc<AtomicBool>,
    advanced: Arc<AtomicBool>,
    // Set whenever the native ledger samples its decision clock.
    sampled: Arc<AtomicBool>,
    _db: crlt::Db,
    _directory: tempfile::TempDir,
}
async fn fixture() -> Fixture {
    fixture_until(2000).await
}
async fn fixture_until(valid_until: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let db = support::open(
        &format!(
            "file://{}",
            directory.path().join("settlement.db").display()
        ),
        "",
    )
    .await;
    let clock = Clock(Arc::new(AtomicI64::new(AT as i64)));
    let late = Arc::new(AtomicBool::new(false));
    let advanced = Arc::new(AtomicBool::new(false));
    let rules_store = cmty::adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
    // Policy's original day-rounded signatures require an independently
    // provisioned key active at day zero, not a fabricated captured signature.
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community(REALM).unwrap()),
        REALM,
        csgn::SecretKey::from_seed(&mut [31; 32]),
        0,
        86_400,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        rules_store,
        PublicationStore {
            inner: cplc::LibsqlStore::new(&db, REALM).unwrap(),
            clock: clock.clone(),
            late: late.clone(),
            advanced: advanced.clone(),
        },
        signer,
        cplc::Config {
            credential_action: ADMISSION_ACTION.into(),
            snapshot_validity: 86_400,
        },
    )
    .await
    .unwrap();
    let mut rules = support::rulebook();
    crbk::RecordEpochSettings::define(&mut rules, PERIOD_KEY).unwrap();
    crbk::OutcomeQuotaSettings::define(&mut rules, QUOTA_KEY).unwrap();
    rules.set_community(PERIOD_KEY, Some(json!(100))).unwrap();
    rules.set_community(QUOTA_KEY, Some(json!(4))).unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: rules,
                announced_at: AT as i64,
                effective_at: AT as i64,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    let mut schema = support::schema(3);
    schema.community = REALM.into();
    policy.set_schema(schema).await.unwrap();
    let trust = AdmissionTrust {
        community_id: REALM.into(),
        policy_digest: B64.encode(&[3; 32]),
        policy_keys: policy.key_ring().unwrap().clone(),
    };
    let store = MemoryStore::default();
    let native_store = store.clone();
    let read = clock.clone();
    let sampled = Arc::new(AtomicBool::new(false));
    let flag = sampled.clone();
    let service = tokio::task::spawn_blocking(move || {
        let ledger = native::ledger(trust, native_store);
        AccountService::new(
            ledger,
            move || {
                flag.store(true, Ordering::SeqCst);
                clbs::Clock::now(&read).unwrap() as u64
            },
            1024 * 1024,
        )
        .unwrap()
        // The public fixture issuer, recorded as the ledger's open issuer key; its
        // certificates bind the fixture community identity.
        .with_extension_issuer(
            cssr::certificate::CertificateIssuer::new(&[3; 32]).unwrap(),
            [0x1d; 32],
        )
        .unwrap()
    })
    .await
    .unwrap();
    let mut rng = cpsd::rand::rngs::StdRng::seed_from_u64(42);
    let gate = cpsd::GateId::new("global-test").unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("original-host-fixture").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let host = Community::new(
        cmty::storage::LibsqlStorage::new(&db, cpsd::CommunityId::new(REALM).unwrap(), 32).unwrap(),
        vec![issuer.public_key().clone()],
        Parts {
            membership: support::members_in(&db, clock.clone(), REALM),
            gates: support::gates_in(&db, REALM),
            policy,
        },
        Config {
            passport: PassportPolicy {
                epoch: 7,
                valid_until: 86_400,
                gates: [gate].into(),
            },
            valid_until,
            challenge_lifetime: 60,
        },
    )
    .unwrap()
    .with_native_account_service(service)
    .await
    .unwrap();
    Fixture {
        host,
        clock,
        store,
        late,
        advanced,
        sampled,
        _db: db,
        _directory: directory,
    }
}

fn issuer() -> (SettlementConfig, SettlementIssuer) {
    let rsa = Rsa::generate(3072).unwrap();
    let raw = Zeroizing::new(rsa.private_key_to_der().unwrap());
    let config: SettlementConfig = serde_json::from_value(json!({
        "epoch": {"purpose":"outcome-deposit-v1", "community":REALM, "epoch":1,
            "valid_from":100_000, "valid_until":200_000,
            "public_key_der":rsa.public_key_to_der().unwrap()},
        "policyEpoch":3, /* the fixture policy epoch after its rulebook and schema installs */ "periodSeconds":100, "quota":4,
        "pendingCapacity":8, "issuanceMembersCapacity":8, "roomEpochs":[]
    }))
    .unwrap();
    let issuer = SettlementIssuer::from_pkcs1_der(config.epoch.clone(), &raw).unwrap();
    (config, issuer)
}
fn clock(clock: Clock) -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(move || clbs::Clock::now(&clock).unwrap() as u64)
}
fn snapshot(store: &mut MemoryStore) -> Vec<(Vec<u8>, Value)> {
    let mut tx = AccountStorage::transaction(store).unwrap();
    let rows = tx.current_range(&[0], &[255], 1024).unwrap();
    tx.rollback().unwrap();
    rows
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_policy_authorizes_daily_mode_and_publishes_its_exact_native_capability() {
    let mut f = fixture().await;
    let shutdown = f.host.account_shutdown().unwrap();
    let (config, issuer) = issuer();
    let feed = f
        .host
        .reconcile_account_settlement(
            PERIOD_KEY,
            QUOTA_KEY,
            config.clone(),
            issuer,
            "host-incarnation".into(),
            clock(f.clock.clone()),
        )
        .await
        .unwrap();
    let policy = f.host.policy().lock().await;
    let signed = policy
        .key_ring()
        .unwrap()
        .verify(
            feed.balance.as_ref().unwrap(),
            csgn::Kind::SettingsSnapshot,
            AT,
        )
        .unwrap();
    let material: cplc::PublicVerifierMaterial = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(material.policy_epoch, policy.epoch(AT).await.unwrap());
    let cap = material.settlement.as_ref().unwrap();
    assert!(cap.epoch == config.epoch);
    assert_eq!(cap.policy_epoch, material.policy_epoch);
    assert_eq!((cap.period_seconds, cap.quota), (100, 4));
    assert!(material.record_epoch.is_none());
    // Bootstrap G5 descriptor authority never fabricates a G2 frontier.
    let durable = snapshot(&mut f.store);
    assert!(
        durable
            .iter()
            .any(|(key, _)| key.as_slice() == b"settlement-mode:v1")
    );
    assert!(!durable.iter().any(|(key, _)| key.first() == Some(&1)));
    drop(policy);
    shutdown.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn awaited_balance_publication_at_exclusive_key_expiry_is_uncertain_and_fences_service() {
    let mut f = fixture().await;
    let shutdown = f.host.account_shutdown().unwrap();
    let (config, issuer) = issuer();
    f.late.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.host
            .reconcile_account_settlement(
                PERIOD_KEY,
                QUOTA_KEY,
                config,
                issuer,
                "host-incarnation".into(),
                clock(f.clock.clone())
            )
            .await,
        Err(Error::Reconcile)
    ));
    assert!(f.advanced.load(Ordering::SeqCst));
    assert_eq!(clbs::Clock::now(&f.clock).unwrap(), 200);
    let stored = cplc::LibsqlStore::new(&f._db, REALM)
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    assert!(serde_json::to_value(stored).unwrap()["balance"]["cose"].is_array());
    let rows = snapshot(&mut f.store);
    assert!(
        rows.iter()
            .any(|(key, _)| key.as_slice() == b"settlement-mode:v1")
    );
    // The real mode and Balance may already have committed. No successful feed
    // or known-no-effect refusal is reported; another native call stays fenced.
    assert!(matches!(
        f.host.publish_account_material(PERIOD_KEY, || 200).await,
        Err(Error::Reconcile)
    ));
    shutdown.shutdown().await.unwrap();
}

// The snapshot deadline of these fixtures: a scheduled boundary of the daily
// owner before the settlement window ends (200).
const OWNER_UNTIL: u64 = 190;

/// Reconcile while the trusted clock jumps to `target` inside the daily owner's
/// commit decision: after the ledger sampled its decision time, during the
/// owner reads. Returns whether the jump happened.
async fn reconcile_across(target: u64) -> (bool, Result<Arc<cplc::cbcn::Feed>>) {
    let f = fixture_until(OWNER_UNTIL).await;
    let shutdown = f.host.account_shutdown().unwrap();
    let (config, issuer) = issuer();
    f.sampled.store(false, Ordering::SeqCst);
    let (sampled, jumped) = (f.sampled.clone(), Arc::new(AtomicBool::new(false)));
    let (done, live) = (jumped.clone(), f.clock.clone());
    let result = f
        .host
        .reconcile_account_settlement(
            PERIOD_KEY,
            QUOTA_KEY,
            config,
            issuer,
            "host-incarnation".into(),
            Arc::new(move || {
                if sampled.load(Ordering::SeqCst) && !done.swap(true, Ordering::SeqCst) {
                    live.0.store(target as i64, Ordering::SeqCst);
                }
                clbs::Clock::now(&live).unwrap() as u64
            }),
        )
        .await;
    shutdown.shutdown().await.unwrap();
    (jumped.load(Ordering::SeqCst), result)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crossed_seconds_inside_daily_owner_reads_commit_without_a_scheduled_boundary() {
    let (jumped, result) = reconcile_across(OWNER_UNTIL - 1).await;
    assert!(jumped);
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_boundary_crossed_inside_daily_owner_reads_refuses_commit() {
    let (jumped, result) = reconcile_across(OWNER_UNTIL).await;
    assert!(jumped);
    assert!(matches!(result, Err(Error::Reconcile)));
}
