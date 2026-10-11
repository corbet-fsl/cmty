//! Current common publication and installed history have distinct meanings.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_public_lookup_installs_current_and_never_rebuilds_expired_history() {
    let (f, value) = member().await;
    let clock = f.clock.clone();
    let slot = NOW / 1000;
    // Historical reads cannot install a root or manufacture an empty object.
    assert!(
        f.engine
            .account_checkpoint(Some(slot), move || clbs::Clock::now(&clock).unwrap() as u64)
            .await
            .unwrap()
            .is_none()
    );
    f.engine
        .enroll_account(
            Arc::new(f.auth.authentication.clone()),
            value,
            NOW,
            Arc::new(Session(f.clock.clone())),
        )
        .await
        .unwrap();
    let clock = f.clock.clone();
    assert!(
        f.engine
            .account_checkpoint(Some(slot), move || clbs::Clock::now(&clock).unwrap() as u64)
            .await
            .unwrap()
            .is_none()
    );
    let clock = f.clock.clone();
    let original = f
        .engine
        .account_checkpoint(None, move || clbs::Clock::now(&clock).unwrap() as u64)
        .await
        .unwrap()
        .unwrap();
    original
        .verify_signature(&SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes())
        .unwrap();
    assert_eq!(original.slot, slot);
    let clock = f.clock.clone();
    let retained = f
        .engine
        .account_checkpoint(Some(slot), move || clbs::Clock::now(&clock).unwrap() as u64)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&retained).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    let clock = f.clock.clone();
    assert!(matches!(
        f.engine
            .account_checkpoint(Some(slot + 1), move || clbs::Clock::now(&clock).unwrap()
                as u64)
            .await,
        Err(Error::Reconcile)
    ));
    // Expiry does not rewrite the original signed historical interval. The
    // public response is explicitly history, never current G1/member authority.
    f.clock.0.store(
        original.expires_at as i64,
        std::sync::atomic::Ordering::SeqCst,
    );
    let clock = f.clock.clone();
    let history = f
        .engine
        .account_checkpoint(Some(slot), move || clbs::Clock::now(&clock).unwrap() as u64)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&history).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
    let clock = f.clock.clone();
    let next = f
        .engine
        .account_checkpoint(None, move || clbs::Clock::now(&clock).unwrap() as u64)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.slot, slot + 1);
    assert_eq!(next.not_before, original.expires_at);
    assert_ne!(next.signature, original.signature);
    f.engine
        .account_shutdown()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}
