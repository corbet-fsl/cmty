//! A real SDK revocation wins over a cancelled queued enrollment command.
use super::*;
use std::{sync::mpsc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_native_ledger_without_common_producer_refuses_enrollment_without_fallback() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let trust = publish_original_balance(&f).await;
    let Outcome::Issued(issued) = issue_account(&mut f, DEVICES[0]).await.unwrap() else {
        panic!("actual admitted member")
    };
    let value = delegation(issued.account.unwrap());
    let read = f.clock.clone();
    let (service, publisher) = services(
        trust,
        f.clock.clone(),
        Box::new(move || clbs::Clock::now(&read).unwrap() as u64),
    )
    .await;
    // This actual configured ledger uses the original single-owner constructor;
    // the unpublished source is dropped rather than replaced by a fake root.
    drop(publisher);
    f.engine = f.engine.with_native_account_service(service).await.unwrap();
    let auth = Arc::new(f.auth.authentication.clone());
    assert!(matches!(
        f.engine
            .enroll_account(auth, value, NOW, Arc::new(Session(f.clock.clone())))
            .await,
        Err(Error::Reconcile)
    ));
    let read = f.clock.clone();
    assert!(matches!(
        f.engine
            .publish_account_checkpoint(move || clbs::Clock::now(&read).unwrap() as u64)
            .await,
        Err(Error::Reconcile)
    ));
    f.engine
        .account_shutdown()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_intake_retains_owners_until_actual_revocation_cut_and_no_root_is_installed() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let trust = publish_original_balance(&f).await;
    let Outcome::Issued(issued) = issue_account(&mut f, DEVICES[0]).await.unwrap() else {
        panic!("actual passport member grant")
    };
    let value = delegation(issued.account.unwrap());
    let runtime = tokio::runtime::Handle::current();
    let keys = ckyh::Passkeys::new(
        ckyh::LibsqlStore::new(&f.db, "example", runtime).unwrap(),
        "example",
        "members.example.org",
        &[ckyh::Url::parse(ORIGIN).unwrap()],
    )
    .unwrap();
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = std::sync::atomic::AtomicBool::new(true);
    let publisher_clock: LiveClock = Box::new(move || {
        if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(30)).unwrap();
        }
        NOW
    });
    let engine =
        Arc::new(install_with_clock(f.engine, trust, f.clock.clone(), publisher_clock).await);
    let policy = engine.policy();
    let shutdown = engine.account_shutdown().unwrap();
    let caller = engine.clone();
    let auth = Arc::new(f.auth.authentication.clone());
    let session: Arc<dyn AccountSession> = Arc::new(Session(f.clock.clone()));
    let task = tokio::spawn(async move { caller.enroll_account(auth, value, NOW, session).await });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(
        policy.try_lock().is_err(),
        "queued worker retains the SAME captured Policy"
    );
    let credential = f.credential_id;
    tokio::task::spawn_blocking(move || keys.revoke(USER, &credential))
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    // Acquiring the actual captured Policy waits for the detached worker's
    // refused commit and guard drop; no guessed delay or authority substitute.
    let held = tokio::time::timeout(Duration::from_secs(30), policy.lock())
        .await
        .unwrap();
    drop(held);
    let read = f.clock.clone();
    assert!(matches!(
        engine
            .publish_account_checkpoint(move || clbs::Clock::now(&read).unwrap() as u64)
            .await,
        Err(Error::Reconcile)
    ));
    // An empty roster still refuses, proving the revoked intake was not made
    // durable even though the original HTTP caller was already cancelled.
    shutdown.shutdown().await.unwrap();
}
