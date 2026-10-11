//! Genuine passport/WebAuthn/Policy/device intake through the combined owner.
//! Checkpoint operations do not invoke a proof or establish initialized custody.
//! The actual native verifier is configured from required authenticated artifacts.
use super::*;
use cmty::cgts::cblc::{enrollment::*, storage::MemoryStore};
#[path = "enrollment/cuts.rs"]
mod cuts;
#[path = "enrollment/history.rs"]
mod history;
#[path = "enrollment/native.rs"]
pub(super) mod native;

type LiveClock = Box<dyn Fn() -> u64 + Send>;

fn delegation(grant: AdmissionGrant) -> AccountingDelegation {
    let device = SigningKey::from_bytes(&[13; 32]);
    let root = SigningKey::from_bytes(&[3; 32]);
    let mut authorization = DeviceAuthorization {
        version: 1,
        community_id: grant.community_id.clone(),
        member_id: grant.member_id.clone(),
        root_public_key: B64.encode(&root.verifying_key().to_bytes()),
        device_public_key: grant.chat_public_key.clone(),
        issued_at: NOW,
        expires_at: grant.expires_at,
        signature: String::new(),
    };
    authorization.signature = B64.encode(
        &root
            .sign(&device_authorization_bytes(&authorization).unwrap())
            .to_bytes(),
    );
    let end = grant.expires_at;
    let mut value = AccountingDelegation {
        version: 1,
        hash_scheme: ACCOUNT_HASH_SCHEME.into(),
        admission: grant,
        authorization,
        // The genuine P-256 generator point, authorized as an independently-held
        // fixture key. No separate P-256 PoP or initialized account is claimed.
        account_public_key: concat!(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )
        .into(),
        state_secret_commitment: format!("{:064x}", 7),
        issued_at: NOW,
        expires_at: end,
        signature: String::new(),
    };
    value.signature = B64.encode(&device.sign(&value.signing_bytes().unwrap()).to_bytes());
    value
}

async fn install(
    engine: Engine<cmty::storage::LibsqlStorage>,
    trust: AdmissionTrust,
    clock: Clock,
) -> Engine<cmty::storage::LibsqlStorage> {
    let read = clock.clone();
    install_with_clock(
        engine,
        trust,
        clock,
        Box::new(move || clbs::Clock::now(&read).unwrap() as u64),
    )
    .await
}

async fn install_with_clock(
    engine: Engine<cmty::storage::LibsqlStorage>,
    trust: AdmissionTrust,
    clock: Clock,
    publisher_clock: LiveClock,
) -> Engine<cmty::storage::LibsqlStorage> {
    let (service, publisher) = services(trust, clock, publisher_clock).await;
    engine
        .with_native_account_enrollment(service, publisher)
        .await
        .unwrap()
}

async fn services(
    trust: AdmissionTrust,
    clock: Clock,
    publisher_clock: LiveClock,
) -> (
    AccountService<NativeAccountVerifier, LiveClock>,
    EnrollmentService<LiveClock>,
) {
    tokio::task::spawn_blocking(move || {
        let store = MemoryStore::default();
        let operator = SigningKey::from_bytes(&[9; 32]);
        let config = EnrollmentConfig {
            community_id: "example".into(),
            policy_digest: trust.policy_digest.clone(),
            operator_public_key: operator.verifying_key().to_bytes(),
            checkpoint_period_seconds: 1000,
            max_members: 16,
            max_retained_slots: 2,
            max_publication_bytes: 1024 * 1024,
        };
        // This is the original actual RAM transaction owner, not an accepting
        // storage callback. Its lack of process restart durability is explicit.
        let ledger = AccountLedger::with_store(
            store.clone(),
            trust,
            ledger_policy(),
            native::verifier(),
            operator.clone(),
        )
        .unwrap();
        let read = clock.clone();
        let ledger_clock: LiveClock = Box::new(move || clbs::Clock::now(&read).unwrap() as u64);
        let service = AccountService::new(ledger, ledger_clock, 1024 * 1024).unwrap();
        let publisher = EnrollmentService::new(
            EnrollmentStore::new(store, config).unwrap(),
            operator,
            publisher_clock,
        )
        .unwrap();
        (service, publisher)
    })
    .await
    .unwrap()
}

async fn member() -> (Fixture<cmty::storage::LibsqlStorage>, AccountingDelegation) {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let trust = publish_original_balance(&f).await;
    let Outcome::Issued(issued) = issue_account(&mut f, DEVICES[0]).await.unwrap() else {
        panic!("actual passport admission and Policy grant")
    };
    let value = delegation(issued.account.unwrap());
    f.engine = install(f.engine, trust, f.clock.clone()).await;
    (f, value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_member_delegation_common_install_and_exact_retry_use_one_native_owner() {
    let (f, value) = member().await;
    let auth = Arc::new(f.auth.authentication.clone());
    let session: Arc<dyn AccountSession> = Arc::new(Session(f.clock.clone()));
    let entry = f
        .engine
        .enroll_account(auth.clone(), value.clone(), NOW, session.clone())
        .await
        .unwrap();
    assert_eq!(entry.member_id, value.admission.member_id);
    assert_eq!(
        entry.delegation_digest,
        data_encoding::HEXLOWER.encode(&value.digest().unwrap())
    );
    let retry = f
        .engine
        .enroll_account(auth, value.clone(), NOW, session)
        .await
        .unwrap();
    assert_eq!(retry, entry);
    let read = f.clock.clone();
    let publication = f
        .engine
        .publish_account_checkpoint(move || clbs::Clock::now(&read).unwrap() as u64)
        .await
        .unwrap();
    assert_eq!(publication.delegations.len(), 1);
    assert_eq!(publication.delegations[0].entry, entry);
    publication
        .verify_signature(&SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes())
        .unwrap();
    let read = f.clock.clone();
    let retry = f
        .engine
        .publish_account_checkpoint(move || clbs::Clock::now(&read).unwrap() as u64)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&retry).unwrap(),
        serde_json::to_vec(&publication).unwrap()
    );
    // No native proof was submitted; the installed common checkpoint is not an
    // accepted account statement, Record proof, wallet opening or G2 result.
    f.engine
        .account_shutdown()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_current_expectations_cannot_enroll_or_publish() {
    let (f, value) = member().await;
    let auth = Arc::new(f.auth.authentication.clone());
    let session: Arc<dyn AccountSession> = Arc::new(Session(f.clock.clone()));
    let mut changed = value.clone();
    changed.admission.passport_policy_digest = B64.encode(&[99; 32]);
    assert!(matches!(
        f.engine
            .enroll_account(auth.clone(), changed, NOW, session.clone())
            .await,
        Err(Error::Membership)
    ));
    // A genuine device signature still cannot alter immutable expected digest.
    let mut changed = value.clone();
    changed.admission.policy_digest = B64.encode(&[98; 32]);
    changed.signature = B64.encode(
        &SigningKey::from_bytes(&[13; 32])
            .sign(&changed.signing_bytes().unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        f.engine
            .enroll_account(auth.clone(), changed, NOW, session.clone())
            .await,
        Err(Error::Reconcile)
    ));
    // Both failed intakes left the original roster empty; no empty publication
    // or root is manufactured by the real publisher.
    let read = f.clock.clone();
    assert!(matches!(
        f.engine
            .publish_account_checkpoint(move || clbs::Clock::now(&read).unwrap() as u64)
            .await,
        Err(Error::Reconcile)
    ));
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    assert!(matches!(
        f.engine.enroll_account(auth, value, NOW, session).await,
        Err(Error::Membership)
    ));
    f.engine
        .account_shutdown()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_common_publisher_does_not_upgrade_a_genuine_member_or_publication() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    publish_original_balance(&f).await;
    let Outcome::Issued(issued) = issue_account(&mut f, DEVICES[0]).await.unwrap() else {
        panic!("genuine grant")
    };
    let value = delegation(issued.account.unwrap());
    assert!(matches!(
        f.engine
            .enroll_account(
                Arc::new(f.auth.authentication),
                value,
                NOW,
                Arc::new(Session(f.clock.clone()))
            )
            .await,
        Err(Error::AccountUnavailable)
    ));
    assert!(matches!(
        f.engine.publish_account_checkpoint(|| NOW).await,
        Err(Error::AccountUnavailable)
    ));
}
