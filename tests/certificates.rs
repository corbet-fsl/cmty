//! Original authenticated-key certificates and actual revocation publication.
#[allow(dead_code)]
mod support;
use cmty::*;
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn current_registered_passkey_certificate_is_separate_from_admission() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let epoch = f.engine.policy().lock().await.epoch(NOW).await.unwrap();
    let bytes = f
        .engine
        .passkey_certificate(&f.auth.authentication, NOW)
        .await
        .unwrap();
    let member = f.passport.pseudonym(&scope()).to_hex();
    let policy = f.engine.policy().lock().await;
    let certificate =
        ckyh::certificate::verify(policy.key_ring().unwrap(), bytes.bytes(), &member, NOW).unwrap();
    assert_eq!(certificate.credential_id(), f.credential_id.as_ref());
    assert_eq!(policy.epoch(NOW).await.unwrap(), epoch);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_key_id_is_published_before_its_original_outbox_generation_is_acknowledged() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let member = f.passport.pseudonym(&scope()).to_hex();
    let original = f
        .engine
        .passkey_certificate(&f.auth.authentication, NOW)
        .await
        .unwrap();
    f.engine
        .membership()
        .revoke_passkey(&f.auth.authentication, f.credential_id.clone())
        .await
        .unwrap();
    assert!(
        f.engine
            .passkey_certificate(&f.auth.authentication, NOW)
            .await
            .is_err()
    );
    assert!(
        !f.engine
            .membership()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.engine.flush_revocations(NOW).await.unwrap(), 1);
    assert!(
        f.engine
            .membership()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
    let mut policy = f.engine.policy().lock().await;
    let ring = policy.key_ring().unwrap().clone();
    // A still-valid certificate signature cannot stand in for the current feed.
    ckyh::certificate::verify(&ring, original.bytes(), &member, NOW).unwrap();
    let bytes = policy
        .publish(cplc::SnapshotKind::RevocationList, NOW)
        .await
        .unwrap();
    let revoked = cplc::verify_snapshot::<cplc::Revocations>(
        &ring,
        &bytes,
        cplc::SnapshotExpectation {
            community: "example",
            kind: cplc::SnapshotKind::RevocationList,
            minimum_revision: 1,
            policy_epoch: policy.epoch(NOW).await.unwrap(),
            now: NOW,
        },
    )
    .unwrap();
    assert!(revoked.content.passkeys.contains(f.credential_id.as_ref()));
    assert_eq!(revoked.content.passkeys.len(), 1);
    drop(policy);
    assert_eq!(f.engine.flush_revocations(NOW).await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_result_carries_actual_owner_completion_instead_of_supplied_start_time() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let completed = NOW + 20;
    f.clock
        .0
        .store(completed as i64, std::sync::atomic::Ordering::SeqCst);
    let issued = f
        .engine
        .passkey_certificate(&f.auth.authentication, NOW)
        .await
        .unwrap();
    assert_eq!(issued.checked_at(), completed);
    assert!(issued.checked_at() > NOW);
    let bytes = issued.bytes().to_vec();
    assert_eq!(issued.into_bytes(), bytes);
    let policy = f.engine.policy().lock().await;
    ckyh::certificate::verify(
        policy.key_ring().unwrap(),
        &bytes,
        &f.passport.pseudonym(&scope()).to_hex(),
        completed,
    )
    .unwrap();
}
