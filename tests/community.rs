//! Full admission through real membership, gatekeeping, policy and libSQL.
mod support;

use cmnt::{storage::MemoryStorage, *};
use cnrl::State;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use support::*;

fn issued(outcome: Outcome) -> Box<IssuedCredential> {
    match outcome {
        Outcome::Issued(value) => value,
        _ => panic!("expected credential"),
    }
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
    assert_eq!(
        serde_json::from_slice::<cplc::Credential>(verified.payload()).unwrap(),
        result.claims.payload().unwrap()
    );
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
        State::Lapsed
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
        Err(Error::Signing)
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
    assert!(matches!(
        f.finish(&challenge, &proof, NOW).await,
        Err(Error::Policy) | Err(Error::Signing)
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
async fn global_suspension_prevents_a_real_holder_from_renewing_in_the_community() {
    // Only the external provider boundary is a fixture. Global issuer, blind
    // wallet, signed status, community proof, membership and signing are real.
    struct Provider;
    impl cglb::GlobalGate for Provider {
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
            _: &cglb::CheckId,
            _: &cglb::Subject,
            _: &[u8],
            _: u64,
        ) -> cglb::Result<cglb::GateEvidence> {
            Ok(cglb::GateEvidence {
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
        "cglb:global",
        csgn::SecretKey::from_seed(&mut [77; 32]),
        NOW,
        30 * 86_400,
    )
    .await
    .unwrap();
    let mut global = cglb::Global::open(
        cglb::storage::MemoryStore::new("global").unwrap(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new("global").unwrap(), 10).unwrap(),
        issuer,
        signer,
        cglb::FingerprintKey::from_bytes(&mut [78; 32]),
        cglb::Mode::Production,
        cglb::Limits {
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
    let policy = cglb::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: expiry,
        gates: vec![cglb::GatePolicy {
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
    let who = cglb::Subject::new("person").unwrap();
    let session = cglb::Session::authenticated(who.clone(), [80; 32]).unwrap();
    global
        .run_gate(
            &Provider,
            &who,
            &[],
            NOW,
            &cglb::CheckId::generate(&mut rng),
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
        .suspend(
            &who,
            cglb::Suspension::Permanent(cglb::PermanentReason::SelfBan),
            NOW,
        )
        .await
        .unwrap();
    let signed_status = global.signed_status(NOW, NOW + 86_400).await.unwrap();
    let status = cglb::Status::verify(
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
