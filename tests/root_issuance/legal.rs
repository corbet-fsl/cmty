//! Actual permanent legal blocks refuse every root-board issuance step.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn order(subject: String, action: &str) -> clbs::SignedOrder {
    let order = clbs::Order {
        community: "example".into(),
        id: format!("deny-{action}"),
        subject,
        reference: "source issuance action fixture".into(),
        entered_by: "fixture-authority".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-authority".into(),
        },
        scope: clbs::Scope::Member,
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    clbs::SignedOrder { order, proof }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_begin_restriction_releases_the_named_admin_and_refuses_begin() {
    let mut w = fixture::world().await;
    let subject = w.holder.pseudonym(w.source.community()).to_hex();
    let legal = clbs::Gate::new(
        cgts::legal_storage::LibsqlStore::new(&w.source_db, "example").unwrap(),
        support::Authority,
    );
    legal
        .record_legal(&order(subject, "root_board_issue_begin"))
        .await
        .unwrap();
    // The order names this admin's own pseudonym, so the enrollment is released
    // at once and the role lookup is refused as well.
    assert!(matches!(
        w.source.membership().role(&w.login.authentication).await,
        Err(cmbr::Error::Restricted)
    ));
    let session = RootBoardSession {
        authentication: &w.login.authentication,
        valid_until: NOW + 120,
        clock: || NOW,
    };
    assert!(matches!(
        w.source
            .begin_root_board_issuance(&w.issuer, &mut w.rng, &session)
            .await,
        Err(cmty::Error::Membership)
    ));
    assert_eq!(w.cut.consumed.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_finish_restriction_after_real_nonce_consumption_withholds_blind_answer() {
    let mut w = fixture::world().await;
    let challenge = w.begin(NOW + 120).await;
    let request = w.request(&challenge);
    let subject = w.holder.pseudonym(w.source.community()).to_hex();
    let legal = clbs::Gate::new(
        cgts::legal_storage::LibsqlStore::new(&w.source_db, "example").unwrap(),
        support::Authority,
    );
    let cut = w.cut.clone();
    cut.mode.store(cuts::PAUSE, Ordering::SeqCst);
    let mut finish = Box::pin(w.finish(&challenge, &request));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = cut.entered.notified() => (),
            answer = &mut finish => panic!("finished before actual nonce cut: {}", answer.is_ok()),
        }
    })
    .await
    .unwrap();
    assert_eq!(cut.consumed.load(Ordering::SeqCst), 1);
    // The source member and Policy guards remain held. This is an independent
    // real legal writer, after root nonce commit and before the source barrier.
    legal
        .record_legal(&order(subject.clone(), "root_board_issue_finish"))
        .await
        .unwrap();
    assert!(matches!(
        legal.check(&subject).await,
        Ok(clbs::State::Red(_))
    ));
    cut.resume.notify_one();
    assert!(matches!(finish.await, Err(cmty::Error::Membership)));
    cut.mode.store(cuts::NORMAL, Ordering::SeqCst);
    // The consumed nonce and the released enrollment each refuse a retry.
    assert!(matches!(
        w.finish(&challenge, &request).await,
        Err(cmty::Error::Passport | cmty::Error::Membership)
    ));
    assert_eq!(cut.consumed.load(Ordering::SeqCst), 1);
}
