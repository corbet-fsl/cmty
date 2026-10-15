//! Full admission through real membership, gatekeeping, policy and libSQL.
mod support;

use cmty::{storage::MemoryStorage, *};
use cnrl::State;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
};
use support::*;

fn issued(outcome: Outcome) -> Box<IssuedCredential> {
    match outcome {
        Outcome::Issued(value) => value,
        _ => panic!("expected credential"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exposed_request_matches_authenticated_signed_request() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let challenge = f.engine.begin(&mut f.rng, NOW).await.unwrap();
    let snapshot = f.engine.snapshot(NOW).await.unwrap();
    let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        f.engine.community().clone(),
        snapshot.signing_keys,
    );
    // Test the public function entry points as well as their inlined callers
    // under this crate's optimized test profile.
    let signed_request: fn(&Challenge) -> &[u8] = std::hint::black_box(Challenge::signed_request);
    let request: fn(&Challenge) -> &cpsd::PresentationRequest =
        std::hint::black_box(Challenge::request);
    let authenticated = origin
        .authenticate(signed_request(&challenge), NOW)
        .unwrap();
    assert_eq!(request(&challenge).to_bytes(), authenticated.to_bytes());
    let proof = present(&f.engine, &f.passport, &mut f.rng, &challenge, NOW).await;
    let verified = f
        .engine
        .verify(&mut f.rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    let member_id: fn(&VerifiedPassport) -> &str =
        std::hint::black_box(VerifiedPassport::member_id);
    assert_eq!(
        member_id(&verified),
        f.passport.pseudonym(&scope()).to_hex()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_passport_passkey_enrolment_gates_policy_pins_and_cose_roundtrip() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let result = issued(f.issue().await);
    assert_eq!(
        result.claims.member_id,
        f.passport.pseudonym(&scope()).to_hex()
    );
    assert_eq!(result.claims.handle, "test_member");
    assert_eq!(result.claims.schema_version, 3);
    assert_eq!(result.claims.valid_until, NOW + NEW_MEMBER_LIFETIME);
    assert_eq!(result.claims.gates.len(), 1);
    assert_eq!(result.claims.gates[0].gate, "dev-test");
    assert_eq!(result.claims.pins["restricted-field"], f.fingerprint);
    assert_eq!(result.claims.devices, DEVICES);
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    let member = f
        .engine
        .membership()
        .member(&f.auth.authentication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.id.as_bytes(), result.claims.member_id.as_bytes());
    let snapshot = f.engine.snapshot(NOW).await.unwrap();
    let verified = snapshot
        .signing_keys
        .verify(&result.cose, csgn::Kind::Credential, NOW)
        .unwrap();
    let signed_payload: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(
        signed_payload.purpose,
        cplc::CredentialPurpose::CommunityAdmission
    );
    assert_eq!(signed_payload.issuance_action, ADMISSION_ACTION);
    assert_eq!(result.claims.purpose, signed_payload.purpose);
    assert_eq!(
        result.claims.issuance_action,
        signed_payload.issuance_action
    );
    assert_eq!(signed_payload, result.claims.payload().unwrap());
    assert_eq!(result.claims.policy_epoch, snapshot.rules.policy_epoch);
    assert!(
        snapshot
            .signing_keys
            .verify(
                &result.cose,
                csgn::Kind::Credential,
                result.claims.valid_until
            )
            .is_err()
    );
    let payload = String::from_utf8(verified.payload().to_vec()).unwrap();
    for forbidden in [
        "global-test",
        "proven_at",
        "last_login",
        "salt",
        "holder_secret",
    ] {
        assert!(!payload.contains(forbidden));
    }
    storage::LibsqlStorage::new(&f.db, scope(), 32)
        .unwrap()
        .check_indexes()
        .await
        .unwrap();
    cgts::LibsqlStore::new(&f.db, "example")
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
    cplc::LibsqlStore::new(&f.db, "example")
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn memory_challenges_compose_with_the_same_real_facades() {
    let mut f = fixture_with(EXPIRY, EXPIRY, |_| MemoryStorage::new(scope(), 32).unwrap()).await;
    assert_eq!(
        issued(f.issue().await).claims.valid_until,
        NOW + NEW_MEMBER_LIFETIME
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn established_cap_and_repeated_renewal_do_not_establish_new_members() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    for _ in 0..3 {
        assert_eq!(
            issued(f.issue().await).claims.valid_until,
            NOW + NEW_MEMBER_LIFETIME
        );
    }
    f.clock.0.store(
        (NOW + 14 * 86_400) as i64,
        std::sync::atomic::Ordering::SeqCst,
    );
    assert_eq!(
        issued(f.issue().await).claims.valid_until,
        NOW + 14 * 86_400 + ESTABLISHED_MEMBER_LIFETIME
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lifetime_adapts_to_gate_policy_passport_and_scheduled_revision() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    issued(f.issue().await);
    f.clock.0.store(
        (NOW + 14 * 86_400) as i64,
        std::sync::atomic::Ordering::SeqCst,
    );
    f.gate((NOW + 16 * 86_400) as i64).await;
    assert_eq!(
        issued(f.issue().await).claims.valid_until,
        NOW + 16 * 86_400
    );
    let mut f = fixture(NOW + 86_400, EXPIRY).await;
    assert_eq!(issued(f.issue().await).claims.valid_until, NOW + 86_400);
    let mut f = fixture(EXPIRY, EXPIRY).await;
    f.engine
        .policy()
        .lock()
        .await
        .schedule_rules(
            Some(1),
            crbk::Change {
                rulebook: f.rules.clone(),
                announced_at: NOW as i64,
                effective_at: (NOW + 120) as i64,
                notice_seconds: 120,
                policy_epoch: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(issued(f.issue().await).claims.valid_until, NOW + 120);
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_withdrawal_lapses_membership_and_fresh_gate_readmits() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    issued(f.issue().await);
    f.withdraw().await;
    match f.issue().await {
        Outcome::Missing(decision) => assert!(!decision.allowed && !decision.missing.is_empty()),
        _ => panic!("missing gate"),
    }
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Lapsed
    );
    f.gate(EXPIRY as i64).await;
    issued(f.issue().await);
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_expiry_lapses_membership_at_the_exclusive_deadline() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    f.gate((NOW + 86_400) as i64).await;
    assert_eq!(issued(f.issue().await).claims.valid_until, NOW + 86_400);
    f.clock
        .0
        .store((NOW + 86_400) as i64, std::sync::atomic::Ordering::SeqCst);
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.finish(&challenge, &proof, NOW + 86_400).await,
        Ok(Outcome::Missing(_))
    ));
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Lapsed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn released_member_cannot_renew_and_handle_release_stays_with_cmbr() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    issued(f.issue().await);
    assert!(f.engine.membership().release(USER).await.is_err());
    let row = f
        .engine
        .membership()
        .revoke_passkey(&f.auth.authentication, f.credential_id.clone())
        .await
        .unwrap();
    assert_eq!(row.state(), State::Released);
    assert_eq!(
        f.engine.membership().release(USER).await.unwrap().state(),
        State::Released
    );
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Membership)
    ));
    let register = crgs::Register::new(
        crgs::LibsqlStorage::new(f.db.community("example").unwrap()),
        crgs::ReleasePeriod::default(),
    );
    let handle = cgrd::check_handle("test_member", &[]).unwrap();
    assert!(
        !register
            .is_handle_available(
                &handle.skeleton,
                chrono::DateTime::from_timestamp(NOW as i64, 0).unwrap()
            )
            .await
            .unwrap()
    );
    let released_at = "2029-10-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    f.clock
        .0
        .store(released_at.timestamp(), std::sync::atomic::Ordering::SeqCst);
    f.engine.membership().maintain(50).await.unwrap();
    assert!(
        register
            .is_handle_available(&handle.skeleton, released_at)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn legal_veto_blocks_issuance_even_with_permissive_policy() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    issued(f.issue().await);
    f.ban().await;
    assert!(matches!(f.issue().await, Outcome::Vetoed));
    assert_eq!(
        f.engine
            .membership()
            .enrolment_state(USER)
            .await
            .unwrap()
            .state(),
        State::Released
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_and_concurrent_submissions_return_at_most_one_credential() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let mut a = StdRng::seed_from_u64(1);
    let mut b = StdRng::seed_from_u64(2);
    let (first, second) = tokio::join!(
        f.engine
            .finish(&mut a, &challenge, &proof, f.admission(), NOW),
        f.engine
            .finish(&mut b, &challenge, &proof, f.admission(), NOW),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(first, Err(Error::Passport)) || matches!(second, Err(Error::Passport)));
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_challenge_community_and_time_fail_without_consuming_valid_proof() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let another = f.engine.begin(&mut f.rng, NOW).await.unwrap();
    assert!(matches!(
        f.finish(&another, &proof, NOW).await,
        Err(Error::Passport)
    ));
    let foreign = cpsd::PresentationRequest::for_epoch(
        &mut f.rng,
        cpsd::CommunityId::new("elsewhere").unwrap(),
        7,
        [cpsd::GateId::new("global-test").unwrap()],
        NOW + 60,
        EXPIRY,
    )
    .unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "elsewhere",
        csgn::SecretKey::from_seed(&mut [42; 32]),
        NOW,
        86_400,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(csgn::Kind::Credential, &foreign.to_bytes(), NOW, NOW + 61)
        .await
        .unwrap();
    let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        foreign.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    let foreign_proof = f
        .passport
        .present(&mut f.rng, &origin, &signed, NOW)
        .unwrap();
    assert!(matches!(
        f.finish(&challenge, &foreign_proof, NOW).await,
        Err(Error::Passport)
    ));
    assert!(matches!(
        f.finish(&challenge, &proof, NOW - 1).await,
        Err(Error::Passport)
    ));
    assert!(matches!(
        f.finish(&challenge, &proof, NOW + 61).await,
        Err(Error::Passport)
    ));
    assert_eq!(f.engine.prune(NOW + 61).await.unwrap(), 2);
    assert!(matches!(
        f.engine.begin(&mut f.rng, 0).await,
        Err(Error::Time)
    ));
    assert!(matches!(
        f.engine.begin(&mut f.rng, u64::MAX).await,
        Err(Error::Time)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_deadline_is_inclusive_but_credential_expiry_is_exclusive() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let result = issued(f.finish(&challenge, &proof, NOW + 60).await.unwrap());
    assert_eq!(result.claims.issued, NOW);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_policy_schema_key_and_epoch_require_new_challenges() {
    for change in 0..4 {
        let mut f = fixture(EXPIRY, EXPIRY).await;
        let (challenge, proof) = f.proof().await;
        {
            let mut policy = f.engine.policy().lock().await;
            match change {
                0 => {
                    policy.bump_epoch().await.unwrap();
                }
                1 => {
                    policy.set_schema(schema(4)).await.unwrap();
                }
                2 => {
                    policy
                        .rotate(csgn::SecretKey::from_seed(&mut [8; 32]), NOW)
                        .await
                        .unwrap();
                }
                _ => {
                    policy
                        .schedule_rules(
                            Some(1),
                            crbk::Change {
                                rulebook: f.rules.clone(),
                                announced_at: NOW as i64,
                                effective_at: (NOW + 1) as i64,
                                notice_seconds: 0,
                                policy_epoch: 2,
                            },
                        )
                        .await
                        .unwrap();
                }
            }
        }
        let at = if change == 3 { NOW + 1 } else { NOW };
        assert!(matches!(
            f.finish(&challenge, &proof, at).await,
            Err(Error::Policy)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn another_valid_passport_cannot_claim_an_authenticated_enrolment() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    // Same authenticated issuer, different blind holder secret.
    let gate = cpsd::GateId::new("global-test").unwrap();
    let mut issuer_rng = StdRng::seed_from_u64(42);
    let issuer = cpsd::IssuerKey::generate(
        &mut issuer_rng,
        cpsd::KeyId::new("shared-issuer").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let secret = cpsd::HolderSecret::generate(&mut f.rng);
    let other = blind_passport(&mut f.rng, &issuer, &secret, gate, EXPIRY, 7).await;
    let challenge = f.engine.begin(&mut f.rng, NOW).await.unwrap();
    let proof = present(&f.engine, &other, &mut f.rng, &challenge, NOW).await;
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Membership)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_gates_run_through_cgts_and_do_not_become_reusable_facts() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    f.withdraw().await;
    let (challenge, proof) = f.proof().await;
    let gate = DevelopmentGate {
        until: (NOW + 100) as i64,
        transient: true,
        fail: false,
    };
    let mut rng = StdRng::seed_from_u64(55);
    let result = f
        .engine
        .finish_with(
            &mut rng,
            &challenge,
            &proof,
            f.admission(),
            NOW,
            async |gates, context| Ok(vec![gates.run(context, &gate, &()).await?]),
        )
        .await
        .unwrap();
    assert_eq!(issued(result).claims.valid_until, NOW + 100);
    assert!(matches!(f.issue().await, Outcome::Missing(_)));
    let (challenge, proof) = f.proof().await;
    let failed = DevelopmentGate {
        until: EXPIRY as i64,
        transient: true,
        fail: true,
    };
    assert!(matches!(
        f.engine
            .finish_with(
                &mut rng,
                &challenge,
                &proof,
                f.admission(),
                NOW,
                async |gates, context| { Ok(vec![gates.run(context, &failed, &()).await?]) }
            )
            .await,
        Err(Error::Gate)
    ));
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_checked_gate_receipts_fail_in_cgts() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let snapshot = f.engine.snapshot(NOW).await.unwrap();
    let subject = f.passport.pseudonym(&scope()).to_hex();
    let gate = DevelopmentGate {
        until: EXPIRY as i64,
        transient: true,
        fail: false,
    };
    for (wrong_subject, wrong_action, wrong_time) in [
        ("other", ADMISSION_ACTION, NOW),
        (subject.as_str(), "other", NOW),
        (subject.as_str(), ADMISSION_ACTION, NOW + 1),
    ] {
        let receipt = f
            .engine
            .gates()
            .run(
                cgts::Context {
                    snapshot: &snapshot.rules,
                    subject: wrong_subject,
                    action: wrong_action,
                    now: wrong_time as i64,
                },
                &gate,
                &(),
            )
            .await
            .unwrap();
        let (challenge, proof) = f.proof().await;
        let mut rng = StdRng::seed_from_u64(99);
        assert!(matches!(
            f.engine
                .finish_with(
                    &mut rng,
                    &challenge,
                    &proof,
                    f.admission(),
                    NOW,
                    async move |_, _| Ok(vec![receipt])
                )
                .await,
            Err(Error::Gate)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_revocation_and_invalid_devices_never_return_credentials() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let mut rng = StdRng::seed_from_u64(66);
    let mut admission = f.admission();
    admission.devices = &[];
    assert!(matches!(
        f.engine
            .finish(&mut rng, &challenge, &proof, admission, NOW)
            .await,
        Err(Error::Membership)
    ));
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
    let subject = f.passport.pseudonym(&scope()).to_hex();
    f.engine
        .policy()
        .lock()
        .await
        .set_revocations(cplc::Revocations {
            members: [subject].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn all_facades_reopen_on_one_database_and_replay_stays_consumed() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let issued = issued(f.finish(&challenge, &proof, NOW).await.unwrap());
    let url = format!(
        "file://{}",
        f.directory.path().join("community.db").display()
    );
    drop(f.engine);
    let db = open(&url, "").await;
    let rules = adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    let policy = cplc::Policy::open(
        rules.clone(),
        cplc::LibsqlStore::new(&db, "example").unwrap(),
        signer,
    )
    .await
    .unwrap();
    let engine = Community::new(
        storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
        Parts {
            membership: members(&db, f.clock),
            gates: gates(&db),
            policy,
        },
        config(EXPIRY, f.config_until),
    )
    .unwrap();
    assert!(
        engine
            .snapshot(NOW)
            .await
            .unwrap()
            .signing_keys
            .verify(&issued.cose, csgn::Kind::Credential, NOW)
            .is_ok()
    );
    assert_eq!(
        engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert!(matches!(
        engine
            .finish(
                &mut f.rng,
                &challenge,
                &proof,
                Admission {
                    authentication: &f.auth.authentication,
                    session: &f.session,
                    creation: None,
                    devices: &DEVICES,
                    lease: crgs::YearMonth::new(2027, 9).unwrap()
                },
                NOW
            )
            .await,
        Err(Error::Passport)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_credential_and_wrong_kind_are_rejected_by_csgn() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let mut result = issued(f.issue().await);
    let snapshot = f.engine.snapshot(NOW).await.unwrap();
    assert!(
        snapshot
            .signing_keys
            .verify(&result.cose, csgn::Kind::SettingsSnapshot, NOW)
            .is_err()
    );
    let last = result.cose.len() - 1;
    result.cose[last] ^= 1;
    assert!(
        snapshot
            .signing_keys
            .verify(&result.cose, csgn::Kind::Credential, NOW)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_provider_missing_action_and_global_proof_age_return_lobby_reasons() {
    for change in 0..3 {
        let mut f = fixture(EXPIRY, EXPIRY).await;
        let mut rules = f.rules.clone();
        match change {
            0 => rules
                .set_community(
                    &crbk::provider_key(crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
                    Some(false.into()),
                )
                .unwrap(),
            1 => {
                // Published catalogues are immutable. Null disables the action
                // without pretending its established definition can be deleted.
                rules
                    .set_community(
                        &crbk::action_key(ADMISSION_ACTION),
                        Some(serde_json::Value::Null),
                    )
                    .unwrap();
            }
            _ => {
                let mut action = crbk::ActionPolicy::default();
                action.all_of.push(crbk::Requirement {
                    gate: "global-test".into(),
                    level: crbk::GateLevel::Global,
                    provider: None,
                });
                action.maximum_proof_age = Some(600);
                rules
                    .set_community(
                        &crbk::action_key(ADMISSION_ACTION),
                        Some(serde_json::to_value(action).unwrap()),
                    )
                    .unwrap();
            }
        }
        f.engine
            .policy()
            .lock()
            .await
            .schedule_rules(
                Some(1),
                crbk::Change {
                    rulebook: rules,
                    announced_at: NOW as i64,
                    effective_at: (NOW + 1) as i64,
                    notice_seconds: 0,
                    policy_epoch: 2,
                },
            )
            .await
            .unwrap();
        f.clock
            .0
            .store((NOW + 1) as i64, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(f.issue().await, Outcome::Missing(_)));
        assert_eq!(
            f.engine
                .membership()
                .resume(&f.auth.authentication)
                .await
                .unwrap()
                .state(),
            State::GatesInProgress
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn competing_signer_fences_issuance_and_consumes_the_presentation() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    f.engine
        .policy()
        .lock()
        .await
        .verified_settings(NOW)
        .await
        .unwrap();
    let _competing = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(f.db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    // Admission commits before the credential is signed, so the fenced signer
    // leaves an uncertain outcome that the caller must reconcile.
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Reconcile)
    ));
    // The fenced policy itself cannot serve another attempt. Check consumption
    // using a fresh real verifier on the same persistent challenge capability.
    assert!(f.finish(&challenge, &proof, NOW).await.is_err());
    let store = storage::LibsqlStorage::new(&f.db, scope(), 32).unwrap();
    let verifier = cpsd::Verifier::new(
        storage::Storage::challenges(&store),
        vec![f.passport.issuer().clone()],
    )
    .unwrap();
    assert!(
        verifier
            .verify(&mut f.rng, challenge.request(), &proof, 7, NOW)
            .await
            .is_err()
    );
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_publication_precedes_acknowledgement_and_fences_existing_credentials() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let credential = issued(f.issue().await);
    f.engine
        .membership()
        .revoke_passkey(&f.auth.authentication, f.credential_id.clone())
        .await
        .unwrap();
    assert!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .is_err()
    );
    assert_eq!(
        f.engine.membership().revocations(10).await.unwrap().len(),
        1
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
    assert!(
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch > credential.claims.policy_epoch
    );
    let policy = f.engine.policy().lock().await;
    assert!(
        policy
            .published(cplc::SnapshotKind::Settings, NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        policy
            .published(cplc::SnapshotKind::RevocationList, NOW)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_revocation_publication_keeps_the_outbox_pending() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    issued(f.issue().await);
    f.engine
        .membership()
        .revoke_passkey(&f.auth.authentication, f.credential_id.clone())
        .await
        .unwrap();
    let competing = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(f.db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    assert!(f.engine.flush_revocations(NOW).await.is_err());
    assert_eq!(
        f.engine.membership().revocations(10).await.unwrap().len(),
        1
    );
    drop(competing);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(f.db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    let policy = cplc::Policy::open(
        adapters::SharedRulebook::new(crbk::LibsqlStore::new(f.db.clone())),
        cplc::LibsqlStore::new(&f.db, "example").unwrap(),
        signer,
    )
    .await
    .unwrap();
    let reopened = Community::new(
        storage::LibsqlStorage::new(&f.db, scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
        Parts {
            membership: members(&f.db, f.clock.clone()),
            gates: gates(&f.db),
            policy,
        },
        config(EXPIRY, EXPIRY),
    )
    .unwrap();
    assert_eq!(reopened.flush_revocations(NOW).await.unwrap(), 1);
    assert!(
        reopened
            .membership()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_gate_releases_policy_mutex_and_changed_policy_refuses_its_receipt() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let entered = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let mut rng = StdRng::seed_from_u64(876);
    let finish = f.engine.finish_with(
        &mut rng,
        &challenge,
        &proof,
        f.admission(),
        NOW,
        async |_, _| {
            entered.notify_one();
            release.notified().await;
            Ok(Vec::new())
        },
    );
    let change = async {
        entered.notified().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), f.engine.snapshot(NOW))
            .await
            .unwrap()
            .unwrap();
        f.engine.policy().lock().await.bump_epoch().await.unwrap();
        release.notify_one();
    };
    let (result, ()) = tokio::join!(finish, change);
    assert!(matches!(result, Err(Error::Policy)));
    assert_ne!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_block_prevents_a_real_holder_from_renewing_in_the_community() {
    // Only the external provider boundary is a fixture. Global issuer, blind
    // wallet, signed status, community proof, membership and signing are real.
    struct Provider;
    impl cgbl::GlobalGate for Provider {
        fn id(&self) -> &str {
            "global-test"
        }
        fn provider(&self) -> &str {
            "external"
        }
        fn development_only(&self) -> bool {
            false
        }
        async fn verify(
            &self,
            _: &cgbl::CheckId,
            _: &cgbl::Subject,
            _: &[u8],
            _: u64,
        ) -> cgbl::Result<cgbl::GateEvidence> {
            Ok(cgbl::GateEvidence {
                valid_until: NOW + 20 * 86_400,
                uniqueness: Some(b"synthetic-normalized-phone".to_vec().into()),
            })
        }
    }
    let expiry = NOW + 20 * 86_400;
    let mut rng = StdRng::seed_from_u64(911);
    let gate = cpsd::GateId::new("global-test").unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("issuer").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cgbl:global",
        csgn::SecretKey::from_seed(&mut [77; 32]),
        NOW,
        30 * 86_400,
    )
    .await
    .unwrap();
    let mut global = cgbl::Global::open(
        cgbl::storage::MemoryStore::new("global").unwrap(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new("global").unwrap(), 10).unwrap(),
        issuer,
        signer,
        cgbl::FingerprintKey::from_bytes(&mut [78; 32]),
        cgbl::Mode::Production,
        cgbl::Limits {
            challenge_ttl: 60,
            pending_capacity: 10,
        },
    )
    .await
    .unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "authority",
        csgn::SecretKey::from_seed(&mut [79; 32]),
        NOW,
        30 * 86_400,
    )
    .await
    .unwrap();
    let policy = cgbl::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: expiry,
        gates: vec![cgbl::GatePolicy {
            gate: "global-test".into(),
            provider: "external".into(),
            uniqueness: true,
        }],
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            NOW,
            expiry + 86_400,
        )
        .await
        .unwrap();
    global
        .install_policy(&signed, authority.key_ring().unwrap(), NOW)
        .await
        .unwrap();
    let who = cgbl::Subject::new("person").unwrap();
    let session = cgbl::Session::authenticated(who.clone(), [80; 32]).unwrap();
    global
        .run_gate(
            &Provider,
            &who,
            &[],
            NOW,
            &cgbl::CheckId::generate(&mut rng),
        )
        .await
        .unwrap();
    let nonce = global
        .challenge(&mut rng, &session, NOW, NOW + 60)
        .await
        .unwrap();
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &nonce).unwrap();
    let blind = global
        .issue(&mut rng, &session, &nonce, &request, NOW)
        .await
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let mut f = fixture_with_identity(
        expiry,
        expiry,
        |db| storage::LibsqlStorage::new(db, scope(), 32).unwrap(),
        Some(passport),
        1,
    )
    .await;
    issued(f.issue().await);
    let (old_challenge, old_proof) = f.proof().await;
    global
        .burn(
            &who,
            cgbl::Burn::Permanent(cgbl::PermanentReason::SelfBan),
            NOW,
        )
        .await
        .unwrap();
    let signed_status = global.signed_status(NOW, NOW + 86_400).await.unwrap();
    let status = cgbl::Status::verify(
        &signed_status,
        global.key_ring().unwrap(),
        "global",
        1,
        1,
        NOW,
    )
    .unwrap();
    f.engine
        .update_passport_policy(PassportPolicy {
            epoch: status.epoch,
            valid_until: status.shared_expiry,
            gates: [gate.clone()].into(),
        })
        .await
        .unwrap();
    assert!(matches!(
        f.finish(&old_challenge, &old_proof, NOW).await,
        Err(Error::Policy)
    ));
    assert!(
        global
            .challenge(&mut rng, &session, NOW, NOW + 60)
            .await
            .is_err()
    );
    let fresh = f.engine.begin(&mut rng, NOW).await.unwrap();
    let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        scope(),
        f.engine.snapshot(NOW).await.unwrap().signing_keys,
    );
    assert!(
        f.passport
            .present(&mut rng, &origin, fresh.signed_request(), NOW)
            .is_err()
    );
    assert!(
        f.engine
            .update_passport_policy(PassportPolicy {
                epoch: 1,
                valid_until: expiry,
                gates: [gate].into()
            })
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_refresh_extends_freshness_and_invalidates_old_challenges() {
    let mut f = fixture(EXPIRY, NOW + 120).await;
    let (old, proof) = f.proof().await;
    let passport = f.engine.snapshot(NOW).await.unwrap().passport;
    f.engine
        .refresh_passport_policy(passport.clone(), NOW + 86_400, NOW)
        .await
        .unwrap();
    assert!(matches!(
        f.finish(&old, &proof, NOW).await,
        Err(Error::Policy)
    ));
    assert!(
        f.engine
            .refresh_passport_policy(passport.clone(), NOW, NOW)
            .await
            .is_err()
    );
    let mut rollback = passport;
    rollback.epoch = 0;
    assert!(
        f.engine
            .refresh_passport_policy(rollback, NOW + 86_400, NOW)
            .await
            .is_err()
    );
    f.clock
        .0
        .store((NOW + 121) as i64, std::sync::atomic::Ordering::SeqCst);
    // The fixture session lasts as long as the first challenge; open a fresh one.
    f.session = Session::new(&f.auth.authentication, EXPIRY);
    let result = issued(f.issue().await);
    let ring = f.engine.snapshot(NOW + 121).await.unwrap().signing_keys;
    ring.verify(&result.cose, csgn::Kind::Credential, NOW + 121)
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn loosening_a_pinned_field_allows_renewal_and_preserves_later_tightening() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    assert_eq!(issued(f.issue().await).claims.pins.len(), 1);
    let mut free = schema(4);
    free.public[0].change_preset = cplc::cshm::ChangePreset::Free;
    f.engine
        .policy()
        .lock()
        .await
        .set_schema(free)
        .await
        .unwrap();
    let renewed = issued(f.issue().await);
    assert_eq!(renewed.claims.schema_version, 4);
    assert!(renewed.claims.pins.is_empty());
    assert!(
        f.engine
            .membership()
            .get_pin(&f.auth.authentication, "restricted-field")
            .await
            .unwrap()
            .is_some()
    );
    f.engine
        .policy()
        .lock()
        .await
        .set_schema(schema(5))
        .await
        .unwrap();
    assert_eq!(
        issued(f.issue().await).claims.pins["restricted-field"],
        f.fingerprint
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_passkey_preserves_admission_after_original_device_removal() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let before = issued(f.issue().await);
    let first_authentication = f.auth.authentication.clone();
    let (options, pending) = f
        .engine
        .begin_additional_registration(&first_authentication)
        .await
        .unwrap();
    let mut second = SoftToken::new(true).unwrap().0;
    let response = second
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let added = f
        .engine
        .finish_additional_registration(&first_authentication, pending, response.into())
        .await
        .unwrap();
    assert_eq!(added.member(), USER);
    let (options, pending) = f
        .engine
        .membership()
        .begin_login(USER, added.credential_id().clone())
        .await
        .unwrap();
    let response = second
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    f.auth = f
        .engine
        .membership()
        .finish_login(pending, response.into())
        .await
        .unwrap();
    // The fixture binds DEVICES[0] to the original passkey only
    // (tests/support/mod.rs). Device authority is passkey-bound, so bind the
    // same lineage key to the surviving passkey before removing the original.
    f.engine
        .membership()
        .authorize_device_key(&f.auth.authentication, DEVICES[0])
        .await
        .unwrap();
    f.engine
        .membership()
        .revoke_passkey(
            &f.auth.authentication,
            first_authentication.credential_id().clone(),
        )
        .await
        .unwrap();
    f.engine.flush_revocations(NOW).await.unwrap();
    assert!(
        f.engine
            .begin_additional_registration(&first_authentication)
            .await
            .is_err()
    );
    assert!(
        f.engine
            .membership()
            .resume(&first_authentication)
            .await
            .is_err()
    );
    f.session = Session::new(&f.auth.authentication, EXPIRY);
    let after = issued(f.issue().await);
    assert_eq!(after.claims.member_id, before.claims.member_id);
    assert_eq!(after.claims.handle, before.claims.handle);
    assert_eq!(after.claims.pins, before.claims.pins);
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    f.engine
        .membership()
        .revoke_passkey(&f.auth.authentication, added.credential_id().clone())
        .await
        .unwrap();
    assert!(
        f.engine
            .begin_additional_registration(&f.auth.authentication)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn constructor_rejects_mismatched_scope_bad_lifetime_empty_keys_and_bad_passport() {
    use std::sync::atomic::AtomicI64;
    // Mismatched scope: storage community differs from the policy key ring issuer.
    {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(42);
        let holder = passport(&mut rng, EXPIRY).await;
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let other = cpsd::CommunityId::new("other").unwrap();
        let attempt = Community::new(
            storage::LibsqlStorage::new(&db, other, 32).unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            config(EXPIRY, EXPIRY),
        );
        assert!(matches!(attempt, Err(Error::Scope)));
    }
    // Bad challenge lifetime: zero and above the five-minute ceiling.
    for lifetime in [0, 301] {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(42);
        let holder = passport(&mut rng, EXPIRY).await;
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let mut bad = config(EXPIRY, EXPIRY);
        bad.challenge_lifetime = lifetime;
        let attempt = Community::new(
            storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            bad,
        );
        assert!(matches!(attempt, Err(Error::Time)));
    }
    // Empty issuer keys.
    {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let attempt = Community::new(
            storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
            Vec::new(),
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            config(EXPIRY, EXPIRY),
        );
        assert!(matches!(attempt, Err(Error::Passport)));
    }
    // Empty passport gates.
    {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(42);
        let holder = passport(&mut rng, EXPIRY).await;
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let mut bad = config(EXPIRY, EXPIRY);
        bad.passport.gates.clear();
        let attempt = Community::new(
            storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            bad,
        );
        assert!(matches!(attempt, Err(Error::Policy)));
    }
    // Passport expiry not aligned to a day boundary.
    {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(42);
        let holder = passport(&mut rng, EXPIRY).await;
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let mut bad = config(EXPIRY, EXPIRY);
        bad.passport.valid_until = EXPIRY + 1;
        let attempt = Community::new(
            storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            bad,
        );
        assert!(matches!(attempt, Err(Error::Policy)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn begin_rejects_collapsed_deadline() {
    // The fixture itself begins, so collapse the deadline afterwards through
    // the authenticated refresh path: snapshot floors stay satisfied while
    // the deadline collapses to now, exercising the deadline time gate.
    let mut f = fixture(EXPIRY, EXPIRY).await;
    f.engine
        .refresh_passport_policy(config(EXPIRY, EXPIRY).passport, NOW + 1, NOW)
        .await
        .unwrap();
    assert!(matches!(
        f.engine.begin(&mut f.rng, NOW).await,
        Err(Error::Time)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn begin_rejects_fenced_signing_request() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    // Drain the legitimate device-key revocation signal instead of excusing
    // it: flush performs its epoch bump and publications, then one more
    // bump without publishing leaves no CURRENT VALID publication, so the
    // premises below still start clean for the fencing phase.
    f.engine.flush_revocations(NOW).await.unwrap();
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    // Premise: the outbox is empty after setup drained the legitimate
    // device-key signal, so begin performs no policy write before the
    // presentation-request signature; the flush drains nothing and the
    // snapshot path is read-only (cplc/crbk loads plus the in-memory ring,
    // all immune to signer fencing).
    assert!(
        f.engine
            .membership()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
    // Premise: no CURRENT VALID settings publication exists after the setup
    // epoch bump (bumping clears signatures without publishing). Begin never
    // publishes, so the first and only signer-store write in begin is the
    // presentation request signature below.
    assert!(
        f.engine
            .policy()
            .lock()
            .await
            .published(cplc::SnapshotKind::Settings, NOW)
            .await
            .unwrap()
            .is_none()
    );
    // Fence the signer store: open advances the stored revision, leaving the
    // engine's in-memory signer revision stale. The next signer write fails.
    let _competing = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(f.db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    // Deterministic phase: flush writes nothing, the snapshot reads succeed,
    // the minted request is in scope with a valid deadline, and only the
    // fenced signature remains. Any other outcome means a premise above broke
    // and must be investigated rather than accepted: exact Signing is required.
    assert!(matches!(
        f.engine.begin(&mut f.rng, NOW).await,
        Err(Error::Signing)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_rejects_stale_proof_and_changed_policy() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let verified = f
        .engine
        .verify(&mut f.rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    // Same community but a different instant than verification.
    assert!(matches!(
        f.engine.begin_registration(verified, USER, NOW + 1).await,
        Err(Error::Passport)
    ));
    let (challenge, proof) = f.proof().await;
    let verified = f
        .engine
        .verify(&mut f.rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    assert!(matches!(
        f.engine.begin_registration(verified, USER, NOW).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_vetoes_transient_gate_refusal() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let mut rng = StdRng::seed_from_u64(77);
    let outcome = f
        .engine
        .finish_with(
            &mut rng,
            &challenge,
            &proof,
            f.admission(),
            NOW,
            async |_, _| Err::<Vec<cgts::CheckedGate>, cgts::Error>(cgts::Error::Vetoed),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Vetoed));
}

#[tokio::test(flavor = "multi_thread")]
async fn update_rejects_empty_gates_misaligned_expiry_and_limit() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let base = f.engine.snapshot(NOW).await.unwrap().passport;
    // Empty gates.
    let mut empty = base.clone();
    empty.gates.clear();
    assert!(matches!(
        f.engine.update_passport_policy(empty).await,
        Err(Error::Policy)
    ));
    // Misaligned expiry.
    let mut skewed = base.clone();
    skewed.valid_until = EXPIRY + 1;
    assert!(matches!(
        f.engine.update_passport_policy(skewed).await,
        Err(Error::Policy)
    ));
    // At the transport time limit.
    let mut capped = base.clone();
    capped.valid_until = cpsd::TIME_LIMIT;
    assert!(matches!(
        f.engine.update_passport_policy(capped).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_rejects_stale_and_misaligned_floors() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let base = f.engine.snapshot(NOW).await.unwrap().passport;
    // Transport freshness at or past the limit.
    assert!(matches!(
        f.engine
            .refresh_passport_policy(base.clone(), cpsd::TIME_LIMIT, NOW)
            .await,
        Err(Error::Policy)
    ));
    // Passport expiry already past.
    let mut stale = base.clone();
    stale.valid_until = NOW;
    assert!(matches!(
        f.engine
            .refresh_passport_policy(stale, NOW + 86_400, NOW)
            .await,
        Err(Error::Policy)
    ));
    // Passport expiry at the limit.
    let mut capped = base.clone();
    capped.valid_until = cpsd::TIME_LIMIT;
    assert!(matches!(
        f.engine
            .refresh_passport_policy(capped, NOW + 86_400, NOW)
            .await,
        Err(Error::Policy)
    ));
    // Misaligned passport expiry.
    let mut skewed = base.clone();
    skewed.valid_until = EXPIRY + 1;
    assert!(matches!(
        f.engine
            .refresh_passport_policy(skewed, NOW + 86_400, NOW)
            .await,
        Err(Error::Policy)
    ));
    // Empty gates.
    let mut empty = base.clone();
    empty.gates.clear();
    assert!(matches!(
        f.engine
            .refresh_passport_policy(empty, NOW + 86_400, NOW)
            .await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_rejects_expired_floors() {
    use std::sync::atomic::AtomicI64;
    // Transport freshness already past: build the engine directly so the
    // fixture handshake does not mask the snapshot floor.
    let directory = tempfile::tempdir().unwrap();
    let db = open(
        &format!("file://{}", directory.path().join("community.db").display()),
        "",
    )
    .await;
    let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
    let mut rng = StdRng::seed_from_u64(42);
    let holder = passport(&mut rng, EXPIRY).await;
    let rules = rulebook();
    let (policy, _) = policies(&db, rules).await;
    let engine = Community::new(
        storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
        vec![holder.issuer().clone()],
        Parts {
            membership: members(&db, clock),
            gates: gates(&db),
            policy,
        },
        config(EXPIRY, NOW),
    )
    .unwrap();
    assert!(matches!(engine.snapshot(NOW).await, Err(Error::Policy)));
    // Expired passport floor installed through the authenticated update path.
    let f = fixture(EXPIRY, EXPIRY).await;
    let mut stale = f.engine.snapshot(NOW).await.unwrap().passport;
    stale.valid_until = 86_400;
    f.engine.update_passport_policy(stale).await.unwrap();
    assert!(matches!(f.engine.snapshot(NOW).await, Err(Error::Policy)));
}

#[tokio::test(flavor = "multi_thread")]
async fn update_rejects_epoch_rollback() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let mut policy = config(EXPIRY, EXPIRY).passport;
    policy.epoch = 6;
    assert!(matches!(
        f.engine.update_passport_policy(policy).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn update_rejects_overlimit_valid_until() {
    // Epoch, gates and alignment all pass, so the TIME_LIMIT arm decides.
    let f = fixture(EXPIRY, EXPIRY).await;
    let mut policy = config(EXPIRY, EXPIRY).passport;
    policy.valid_until = cpsd::TIME_LIMIT.div_ceil(86_400) * 86_400;
    assert!(matches!(
        f.engine.update_passport_policy(policy).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_rejects_limit_floors() {
    // Community::new leaves config horizons to the snapshot floors; both
    // the passport and the config arm above TIME_LIMIT must fail closed.
    // TIME_LIMIT itself is not day-aligned, so round up to a multiple the
    // constructor accepts.
    let limit = cpsd::TIME_LIMIT.div_ceil(86_400) * 86_400;
    for (expiry, valid_until) in [(limit, EXPIRY), (EXPIRY, cpsd::TIME_LIMIT)] {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("limit.db").display()),
            "",
        )
        .await;
        let clock = Clock(std::sync::Arc::new(AtomicI64::new(NOW as i64)));
        let mut rng = StdRng::seed_from_u64(4242);
        let holder = passport(&mut rng, EXPIRY).await;
        let rules = rulebook();
        let (policy, _) = policies(&db, rules).await;
        let engine = Community::new(
            storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
            vec![holder.issuer().clone()],
            Parts {
                membership: members(&db, clock),
                gates: gates(&db),
                policy,
            },
            config(expiry, valid_until),
        )
        .unwrap();
        assert!(matches!(engine.snapshot(NOW).await, Err(Error::Policy)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_fails_when_settings_publication_is_fenced() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    // Drain the legitimate device-key revocation signal instead of excusing
    // it: flush performs its epoch bump and publications, then one more
    // bump without publishing leaves no CURRENT VALID publication, so the
    // premises below still start clean for the fencing phase.
    f.engine.flush_revocations(NOW).await.unwrap();
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    // Premise: the outbox is empty after setup drained the legitimate
    // device-key signal, so the run performs no policy write before the
    // settings publication; resume and gate inputs are healthy.
    assert!(
        f.engine
            .membership()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
    // Premise: no CURRENT VALID settings publication exists after the setup
    // epoch bump (bumping clears signatures without publishing). Verified
    // settings therefore must publish inside this run; that publication is
    // the first policy write after the read-only snapshot phase.
    assert!(
        f.engine
            .policy()
            .lock()
            .await
            .published(cplc::SnapshotKind::Settings, NOW)
            .await
            .unwrap()
            .is_none()
    );
    // The challenge predates the fence, and the stored rulebook is untouched
    // by signer fencing, so verification and both snapshot reads succeed.
    let (challenge, proof) = f.proof().await;
    // Fence the signer store only. The fence cannot affect the cplc load
    // comparison in current(), so the failure lands exactly at the publish
    // inside verified_settings: community.rs:343.
    let _competing = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(f.db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
    )
    .await
    .unwrap();
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Policy)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_vetoes_gate_check_after_transient_legal_record() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (challenge, proof) = f.proof().await;
    let mut rng = StdRng::seed_from_u64(78);
    // Resume already passed with a Green legal state. The transient callback
    // records a real legal order through the real clbs leaf, so the later
    // persistent gate check observes Red while every receipt stays valid.
    let db = f.db.clone();
    let subject = f.passport.pseudonym(&scope()).to_hex();
    let outcome = f
        .engine
        .finish_with(
            &mut rng,
            &challenge,
            &proof,
            f.admission(),
            NOW,
            async move |_, _| {
                let order = clbs::Order {
                    community: "example".into(),
                    id: "legal-test".into(),
                    subject: subject.clone(),
                    reference: "synthetic-authority".into(),
                    entered_by: "authority".into(),
                    kind: clbs::OrderKind::Legal {
                        authority: "test-authority".into(),
                    },
                };
                let proof_bytes = SigningKey::from_bytes(&[7; 32])
                    .sign(&order.signing_payload().unwrap())
                    .to_bytes()
                    .to_vec();
                clbs::Gate::new(
                    cgts::legal_storage::LibsqlStore::new(&db, "example").unwrap(),
                    Authority,
                )
                .record_legal(&clbs::SignedOrder {
                    order,
                    proof: proof_bytes,
                })
                .await
                .unwrap();
                Ok(Vec::new())
            },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Vetoed));
}

/// A second community built from real facades on an isolated database. Only
/// begin/verify are used, so membership enrolment is unnecessary; every store
/// is real and every signature verifies.
async fn foreign_material() -> (Challenge, VerifiedPassport, crlt::Db, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let db = open(
        &format!("file://{}", directory.path().join("foreign.db").display()),
        "",
    )
    .await;
    let clock = Clock(Arc::new(AtomicI64::new(NOW as i64)));
    let mut rng = StdRng::seed_from_u64(43);
    let holder = passport(&mut rng, EXPIRY).await;
    let store = adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community("other").unwrap()),
        "other",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
        ESTABLISHED_MEMBER_LIFETIME,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        store,
        cplc::LibsqlStore::new(&db, "other").unwrap(),
        signer,
        cplc::Config {
            credential_action: ADMISSION_ACTION.into(),
            snapshot_validity: 86_400,
        },
    )
    .await
    .unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: rulebook(),
                announced_at: NOW as i64,
                effective_at: NOW as i64,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    let other_schema: cplc::cshm::Schema = serde_json::from_value(serde_json::json!({ "community":"other", "version":3,
        "public":[{"id":"restricted-field","label":"Restricted field", "kind":{"type":"yes_no"},
        "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}], "private":[] }))
    .unwrap();
    policy.set_schema(other_schema).await.unwrap();
    // Membership and gates reuse the proven constructors; this engine never
    // enrols, so their namespaces stay idle while begin/verify run for real.
    let engine = Community::new(
        storage::LibsqlStorage::new(&db, cpsd::CommunityId::new("other").unwrap(), 32).unwrap(),
        vec![holder.issuer().clone()],
        Parts {
            membership: members_in(&db, clock, "other"),
            gates: gates_in(&db, "other"),
            policy,
        },
        config(EXPIRY, EXPIRY),
    )
    .unwrap();
    let challenge = engine.begin(&mut rng, NOW).await.unwrap();
    let proof = present(&engine, &holder, &mut rng, &challenge, NOW).await;
    let verified = engine
        .verify(&mut rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    (challenge, verified, db, directory)
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_rejects_foreign_community_challenge() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (foreign_challenge, _foreign_verified, _db, _directory) = foreign_material().await;
    let (_, local_proof) = f.proof().await;
    let mut rng = StdRng::seed_from_u64(5);
    // The foreign challenge binds community "other" with a fresh deadline, so
    // only the community comparison can fail, before any proof is consumed.
    assert!(matches!(
        f.engine
            .finish(
                &mut rng,
                &foreign_challenge,
                &local_proof,
                f.admission(),
                NOW
            )
            .await,
        Err(Error::Passport)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn begin_registration_rejects_foreign_verified_community() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let (_challenge, foreign_verified, _db, _directory) = foreign_material().await;
    // Same instant, so only the community comparison can fail: the passport
    // is genuinely verified, but for "other" instead of "example".
    assert!(matches!(
        f.engine
            .begin_registration(foreign_verified, USER, NOW)
            .await,
        Err(Error::Passport)
    ));
}

/// Test-only challenge store that rendezvous exactly once with a concurrent
/// mutation. After the wrapped store successfully consumes a challenge while
/// armed, it notifies the waiter, holds the actual result until released,
/// then returns it unchanged. All other calls delegate untouched, and a
/// disarmed store never rendezvous, so fixture and proof setup behave exactly
/// as with the plain store.
#[derive(Clone)]
struct RendezvousChallenges<S> {
    inner: S,
    gate: ConsumeGate,
}

/// Shared armed one-shot gate for the consume rendezvous.
#[derive(Clone)]
struct ConsumeGate {
    state: Arc<std::sync::Mutex<ConsumeGateState>>,
}

struct ConsumeGateState {
    armed: bool,
    fired: bool,
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ConsumeGate {
    fn new() -> (
        Self,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        (
            Self {
                state: Arc::new(std::sync::Mutex::new(ConsumeGateState {
                    armed: false,
                    fired: false,
                    entered: Some(entered_tx),
                    release: Some(release_rx),
                })),
            },
            entered_rx,
            release_tx,
        )
    }

    /// Arm after fixture and proof setup so earlier consumes pass through.
    fn arm(&self) {
        self.state.lock().expect("consume gate lock").armed = true;
    }

    fn fired(&self) -> bool {
        self.state.lock().expect("consume gate lock").fired
    }
}

impl<S: cpsd::ChallengeStore> cpsd::ChallengeStore for RendezvousChallenges<S> {
    fn community(&self) -> &cpsd::CommunityId {
        self.inner.community()
    }

    async fn reserve(
        &self,
        record: cpsd::ChallengeRecord,
    ) -> std::result::Result<bool, cpsd::Error> {
        self.inner.reserve(record).await
    }

    async fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: cpsd::Timestamp,
    ) -> std::result::Result<bool, cpsd::Error> {
        self.inner.matches(nonce, binding, now).await
    }

    async fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: cpsd::Timestamp,
    ) -> std::result::Result<bool, cpsd::Error> {
        let outcome = self.inner.consume(nonce, binding, now).await;
        let release = {
            let mut gate = self.gate.state.lock().expect("consume gate lock");
            if matches!(&outcome, Ok(true)) && gate.armed {
                gate.armed = false;
                gate.fired = true;
                if let Some(entered) = gate.entered.take() {
                    // The waiter holds the matching receiver; loss means it
                    // already gave up, which the timeout below reports.
                    let _ = entered.send(());
                }
                gate.release.take()
            } else {
                None
            }
        };
        if let Some(release) = release {
            // The mutation future is concurrently polled and must release
            // right after its bump, proving it completed BEFORE consume
            // returns. Anything else fails closed here.
            tokio::time::timeout(std::time::Duration::from_secs(10), release)
                .await
                .expect("mutation release")
                .expect("release sender alive");
        }
        outcome
    }

    async fn prune(&self, now: cpsd::Timestamp) -> std::result::Result<u64, cpsd::Error> {
        self.inner.prune(now).await
    }
}

/// Test-only community storage that shares the consume gate with the engine's
/// verifier challenge store. Everything else delegates to the real store.
#[derive(Clone)]
struct RendezvousStorage {
    inner: storage::LibsqlStorage,
    gate: ConsumeGate,
}

impl storage::Storage for RendezvousStorage {
    type Challenges = RendezvousChallenges<cpsd::storage::libsql::LibsqlStore>;

    fn challenges(&self) -> Self::Challenges {
        RendezvousChallenges {
            inner: self.inner.challenges(),
            gate: self.gate.clone(),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_rejects_policy_changed_during_verification() {
    let (gate, entered_rx, release_tx) = ConsumeGate::new();
    let mut f = fixture_with(EXPIRY, EXPIRY, |db| RendezvousStorage {
        inner: storage::LibsqlStorage::new(db, scope(), 32).unwrap(),
        gate: gate.clone(),
    })
    .await;
    // Same legitimate-work drain as the fencing tests: the fixture device-key
    // binding signals a revocation, so flush it properly and bump once more
    // without publishing. Proof generation follows setup, so both snapshots
    // in finish observe the post-setup epoch.
    f.engine.flush_revocations(NOW).await.unwrap();
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    let (challenge, proof) = f.proof().await;
    // The consume inside finish's verify is the deterministic rendezvous
    // point: cpsd verifies the real proof, then awaits ChallengeStore
    // consume before returning, while cmty snapshots policy again right
    // after verify returns. Firing there lands the bump strictly between
    // the two policy observations, after real cryptographic success.
    gate.arm();
    let epoch_before = f.engine.policy().lock().await.epoch(NOW).await.unwrap();
    // Field-precise borrows (as in Fixture::finish): the admission holds
    // shared field borrows only, disjoint from the mutable rng borrow below.
    let admission = Admission {
        authentication: &f.auth.authentication,
        session: &f.session,
        creation: None,
        devices: &DEVICES,
        lease: crgs::YearMonth::new(2027, 9).unwrap(),
    };
    let (result, ()) = tokio::join!(
        f.engine
            .finish(&mut f.rng, &challenge, &proof, admission, NOW),
        async {
            // Fail closed: without a fired consume there is nothing to race,
            // and without a delivered release the mutation did not complete
            // before consume returns.
            tokio::time::timeout(std::time::Duration::from_secs(30), entered_rx)
                .await
                .expect("consume gate must fire")
                .expect("entered sender alive");
            // Same engine handle and store as production: no second signer
            // instance, so no accidental fencing. The bump must succeed.
            f.engine
                .policy()
                .lock()
                .await
                .bump_epoch()
                .await
                .expect("mutation bump must succeed");
            release_tx.send(()).expect("release receiver alive");
        }
    );
    let epoch_after = f.engine.policy().lock().await.epoch(NOW).await.unwrap();
    assert!(
        gate.fired(),
        "consume gate must fire after real proof verification"
    );
    assert_eq!(
        epoch_before + 1,
        epoch_after,
        "mutation bump must advance the epoch exactly once"
    );
    assert!(matches!(result, Err(Error::Policy)));
}

#[tokio::test(flavor = "multi_thread")]
async fn issuance_skips_unpinned_stable_fields() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    // A second stable field that was never sealed exercises the missing-pin
    // skip: validation accepts partial pins, so issuance still succeeds with
    // exactly the sealed fingerprint collected.
    let two: cplc::cshm::Schema = serde_json::from_value(serde_json::json!({ "community":"example", "version":4,
        "public":[
            {"id":"restricted-field","label":"Restricted field", "kind":{"type":"yes_no"}, "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false},
            {"id":"extra-field","label":"Extra field", "kind":{"type":"yes_no"}, "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}
        ], "private":[] }))
    .unwrap();
    f.engine
        .policy()
        .lock()
        .await
        .set_schema(two)
        .await
        .unwrap();
    let result = issued(f.issue().await);
    assert_eq!(result.claims.schema_version, 4);
    assert_eq!(result.claims.pins.len(), 1);
    assert_eq!(result.claims.pins["restricted-field"], f.fingerprint);
}

/// Test-only fault injection around the real libSQL policy store. Every call
/// delegates to the live backend; only the Nth compare-exchange after arming
/// fails, exercising genuine commit-failure handling without mocking logic.
struct FailNthCommit<P> {
    inner: P,
    control: Arc<FailControl>,
    fail_at: usize,
}

struct FailControl {
    armed: AtomicBool,
    writes: AtomicUsize,
}

impl<P: cplc::Storage> cplc::Storage for FailNthCommit<P> {
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
        if self.control.armed.load(Ordering::SeqCst)
            && self.control.writes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at
        {
            return Err(cplc::Error::Conflict);
        }
        self.inner.compare_exchange(expected, next).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn flush_rejects_second_publication_commit_failure() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let directory = tempfile::tempdir().unwrap();
    let db = open(
        &format!("file://{}", directory.path().join("wrapped.db").display()),
        "",
    )
    .await;
    let clock = Clock(Arc::new(AtomicI64::new(NOW as i64)));
    let mut rng = StdRng::seed_from_u64(42);
    let holder = passport(&mut rng, EXPIRY).await;
    // The wrapper passes everything through until armed; enrolment and the
    // revocation below therefore run against the real backend untouched.
    let control = Arc::new(FailControl {
        armed: AtomicBool::new(false),
        writes: AtomicUsize::new(0),
    });
    let wrapped = FailNthCommit {
        inner: cplc::LibsqlStore::new(&db, "example").unwrap(),
        control: control.clone(),
        fail_at: 3,
    };
    let store = adapters::SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community("example").unwrap()),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
        ESTABLISHED_MEMBER_LIFETIME,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        store,
        wrapped,
        signer,
        cplc::Config {
            credential_action: ADMISSION_ACTION.into(),
            snapshot_validity: 86_400,
        },
    )
    .await
    .unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: rulebook(),
                announced_at: NOW as i64,
                effective_at: NOW as i64,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    policy.set_schema(schema(3)).await.unwrap();
    let engine = Community::new(
        storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
        vec![holder.issuer().clone()],
        Parts {
            membership: members(&db, clock),
            gates: gates(&db),
            policy,
        },
        config(EXPIRY, EXPIRY),
    )
    .unwrap();
    // Shortened enrolment: only an authenticated login is needed before the
    // passkey revocation that arms the outbox. Pins, handles and gates play
    // no role in the revocation drain below.
    let challenge = engine.begin(&mut rng, NOW).await.unwrap();
    let ring = engine.snapshot(NOW).await.unwrap().signing_keys;
    let origin =
        cpsd::AuthenticatedCommunity::from_authenticated_origin(engine.community().clone(), ring);
    let proof = holder
        .present(&mut rng, &origin, challenge.signed_request(), NOW)
        .unwrap();
    let verified = engine
        .verify(&mut rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    let (request, pending) = engine
        .begin_registration(verified, USER, NOW)
        .await
        .unwrap();
    let mut device = SoftToken::new(true).unwrap().0;
    let response = device
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                let mut options = request.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let credential_id: ckyh::CredentialID = response.raw_id.clone().into();
    engine
        .membership()
        .finish_registration(pending, response.into())
        .await
        .unwrap();
    let (login_request, login_pending) = engine
        .membership()
        .begin_login(USER, credential_id.clone())
        .await
        .unwrap();
    let login_response = device
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            login_request.public_key,
            300_000,
        )
        .unwrap();
    let auth = engine
        .membership()
        .finish_login(login_pending, login_response.into())
        .await
        .unwrap();
    let _revoked = engine
        .membership()
        .revoke_passkey(&auth.authentication, credential_id)
        .await
        .unwrap();
    // Exactly one pending event, so the drain performs exactly three policy
    // commits in order: epoch bump, settings publication, revocation-list
    // publication. Only member reads happen between arming and the drain.
    assert_eq!(engine.membership().revocations(10).await.unwrap().len(), 1);
    control.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        engine.flush_revocations(NOW).await,
        Err(Error::Policy)
    ));
    // The failed second publication leaves the outbox pending for retry.
    assert_eq!(engine.membership().revocations(10).await.unwrap().len(), 1);
}
