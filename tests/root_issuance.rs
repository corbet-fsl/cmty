//! Real source-role issuance into the existing same-holder root credential.
//! Role setup provisions an existing register role after actual admission.
#[path = "root_issuance/cuts.rs"]
mod cuts;
#[path = "root_issuance/fixture.rs"]
mod fixture;
#[path = "root_issuance/legal.rs"]
mod legal;
mod support;

use cmty::*;
use cpsd::{
    rand::{SeedableRng, rngs::StdRng},
    *,
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use std::time::Duration;
use support::{Clock, DEVICES, EXPIRY, Engine, NOW, ORIGIN, USER};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_source_admin_issues_once_and_original_holder_proves_root_admission() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    let blind = w.finish(&challenge, &request).await.unwrap();
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
    w.holder.finish_root_board_issuance(&blind).unwrap();
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Passport)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
    let root_challenge = w.root.begin(&mut w.rng, NOW).await.unwrap();
    let proof = w
        .holder
        .present_root_board(
            &mut w.rng,
            &w.root_expected,
            root_challenge.signed_request(),
            NOW,
        )
        .unwrap();
    let verified = w
        .root
        .verify_root_board(&root_challenge, &proof, NOW)
        .await
        .unwrap();
    assert_eq!(
        verified.member_id(),
        w.holder.pseudonym(w.root.community()).to_hex()
    );
    assert_ne!(
        verified.member_id(),
        w.holder.pseudonym(w.source.community()).to_hex()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_other_holder_is_not_the_authenticated_source_role_and_nonce_stays_usable() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let mut other = fixture::passport(&mut w.rng, &w.global, 99).await;
    let wrong = other
        .begin_root_board_issuance(
            &mut w.rng,
            &w.root_expected,
            challenge.signed_context(),
            &w.source_expected,
            challenge.signed_source_request(),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        w.finish(&challenge, &wrong).await,
        Err(cmty::Error::Membership)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
    let original = w.request(&challenge);
    let blind = w.finish(&challenge, &original).await.unwrap();
    w.holder.finish_root_board_issuance(&blind).unwrap();
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_register_demotion_refuses_before_root_nonce_consumption() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    w.source
        .membership()
        .set_role(
            &w.login.authentication,
            w.login.authentication.member(),
            crgs::Role::Member,
        )
        .await
        .unwrap();
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Membership)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
    assert_eq!(
        w.source
            .membership()
            .resume(&w.login.authentication)
            .await
            .unwrap()
            .state(),
        cmbr::State::Admitted
    );
    let row = w
        .source
        .membership()
        .resume(&w.login.authentication)
        .await
        .unwrap();
    let member = crgs::Register::new(
        crgs::LibsqlStorage::new(w.source_db.community("example").unwrap()),
        crgs::ReleasePeriod::default(),
    )
    .member(&row.member_id())
    .await
    .unwrap()
    .unwrap();
    assert_eq!(member.role, crgs::Role::Member);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inclusive_context_is_strictly_inside_the_actual_exclusive_source_session() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 10).await;
    assert_eq!(w.context(&challenge).await.deadline(), NOW + 9);
    assert_eq!(challenge.valid_until(), NOW + 10);
    let request = w.request(&challenge);
    w.clock.0.store((NOW + 10) as i64, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Time)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_root_purpose_key_and_root_source_alias_never_become_issuers() {
    let mut w = fixture::world().await;
    let wrong = IssuerKey::generate(
        &mut w.rng,
        KeyId::new("wrong-root").unwrap(),
        vec![GateId::new("root-board").unwrap()],
    )
    .unwrap();
    assert!(matches!(
        w.root.root_board_issuer(wrong, NOW).await,
        Err(cmty::Error::Policy)
    ));
    let session = RootBoardSession {
        authentication: &w.login.authentication,
        valid_until: NOW + 120,
        clock: || NOW,
    };
    assert!(matches!(
        w.root
            .begin_root_board_issuance(&w.issuer, &mut w.rng, &session)
            .await,
        Err(cmty::Error::Scope)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_policy_epoch_replacement_refuses_the_old_signed_context_without_consuming_it() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    {
        let mut policy = w.root.policy().lock().await;
        let mut schema = support::schema(4);
        schema.community = "root".into();
        policy.set_schema(schema).await.unwrap();
        let next = RootBoardPublicKey::from_authenticated_beacon(
            w.descriptor.issuer().clone(),
            CommunityId::new("root").unwrap(),
            policy.epoch(NOW).await.unwrap(),
            w.descriptor.cohort_start(),
        )
        .unwrap();
        policy.publish_root_board(&next, NOW).await.unwrap();
    }
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Policy)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_next_effective_policy_shortens_the_original_context() {
    let mut w = fixture::world().await;
    w.source
        .policy()
        .lock()
        .await
        .schedule_rules(
            Some(1),
            crbk::Change {
                rulebook: support::rulebook(),
                announced_at: NOW as i64,
                effective_at: (NOW + 30) as i64,
                notice_seconds: 0,
                policy_epoch: 2,
            },
        )
        .await
        .unwrap();
    let challenge = w.begin(NOW + 120).await;
    assert_eq!(w.context(&challenge).await.deadline(), NOW + 29);
    assert_eq!(challenge.valid_until(), NOW + 30);
    let request = w.request(&challenge);
    w.clock.0.store((NOW + 30) as i64, Ordering::SeqCst);
    assert!(w.finish(&challenge, &request).await.is_err());
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_after_real_sql_consumption_burns_the_attempt_without_a_blind_answer() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    let deadline = w.context(&challenge).await.deadline();
    w.cut
        .after_time
        .store((deadline + 1) as i64, Ordering::SeqCst);
    w.cut.mode.store(cuts::EXPIRE, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Time)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advance_then_rollback_above_initial_time_after_consumption_never_releases() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    w.cut.mode.store(cuts::ROLLBACK, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Time)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
    assert!(w.cut.clock_samples.load(Ordering::SeqCst) >= 2);
    assert_eq!(w.clock.0.load(Ordering::SeqCst), (NOW + 15) as i64);
    w.cut.mode.store(cuts::NORMAL, Ordering::SeqCst);
    w.clock.0.store((NOW + 20) as i64, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Passport)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_after_actual_sql_consumption_burns_nonce_and_releases_real_guards() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    let cut = w.cut.clone();
    cut.mode.store(cuts::PAUSE, Ordering::SeqCst);
    let mut finish = Box::pin(w.finish(&challenge, &request));
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            _ = cut.entered.notified() => (),
            answer = &mut finish => panic!("source finished before the storage cancellation cut: {}", answer.is_ok()),
        }
    }).await.unwrap();
    assert_eq!(cut.consumed.load(Ordering::SeqCst), 1);
    drop(finish);
    cut.mode.store(cuts::NORMAL, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Passport)
    ));
    tokio::time::timeout(
        Duration::from_secs(3),
        w.source.membership().set_role(
            &w.login.authentication,
            w.login.authentication.member(),
            crgs::Role::Member,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(w.source.policy().try_lock().is_ok());
    assert!(w.root.policy().try_lock().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advancing_only_the_final_release_cut_never_returns_the_blind_answer() {
    // Calibrate the genuine successful path, including its real writer barrier
    // and synchronous CPSD signing. The direct clock has no authority shortcut.
    let mut original = fixture::world().await;
    let challenge = original.begin(NOW + 120).await;
    let request = original.request(&challenge);
    original.cut.direct_samples.store(0, Ordering::SeqCst);
    let blind = original.finish(&challenge, &request).await.unwrap();
    original.holder.finish_root_board_issuance(&blind).unwrap();
    let final_sample = original.cut.direct_samples.load(Ordering::SeqCst);
    assert!(final_sample > 1);
    assert_eq!(original.cut.consumed.load(Ordering::SeqCst), 1);

    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    w.cut.direct_samples.store(0, Ordering::SeqCst);
    w.cut.advance_at.store(final_sample, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Time)
    ));
    assert_eq!(w.cut.direct_samples.load(Ordering::SeqCst), final_sample);
    assert_eq!(w.clock.0.load(Ordering::SeqCst), (NOW + 1) as i64);
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
    w.cut.advance_at.store(0, Ordering::SeqCst);
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Passport)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 1);
}
