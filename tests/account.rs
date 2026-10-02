//! The real member lease and current passkey bind the original Balance service.
//! Signed status is exercised without claiming a ZK account-transition proof.
mod support;
use cmty::{
    cgts::cblc::{accounting::*, accounting_ledger::*, accounting_service::*, admission::*},
    *,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use support::*;

fn policy_signer() -> csgn::Signer {
    csgn::Signer::new(
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW - 1,
        EXPIRY - NOW + 1,
    )
    .unwrap()
}

async fn service<C: Fn() -> u64 + Send + 'static>(
    path: std::path::PathBuf,
    clock: C,
) -> AccountService<ProcessAccountVerifier, C> {
    service_with_trust(
        path,
        clock,
        AdmissionTrust {
            community_id: "example".into(),
            policy_digest: B64.encode(&[4; 32]),
            policy_keys: policy_signer().key_ring().clone(),
        },
    )
    .await
}

fn ledger_policy() -> AccountLedgerPolicy {
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: NOW - 1,
            policy_valid_until: EXPIRY,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 4 * 1024 * 1024,
        checkpoint_period_seconds: 1000,
    }
}

async fn service_with_trust<C: Fn() -> u64 + Send + 'static>(
    path: std::path::PathBuf,
    clock: C,
    trust: AdmissionTrust,
) -> AccountService<ProcessAccountVerifier, C> {
    tokio::task::spawn_blocking(move || {
        let verifier = ProcessAccountVerifier::new(ProcessVerifierConfig {
            node: "/unconfigured/node".into(),
            script: "/unconfigured/worker.mjs".into(),
            artifact_config: "/unconfigured/artifacts.json".into(),
            scope: AccountProofScope {
                circuit_digest: [51; 32],
                verifying_key_digest: [52; 32],
            },
            timeout: Duration::from_secs(1),
            maximum_parallel: 1,
            max_proof_bytes: 1024,
            node_heap_megabytes: 64,
        })
        .unwrap();
        let policy = ledger_policy();
        let ledger = AccountLedger::open(
            path,
            trust,
            policy,
            verifier,
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap();
        AccountService::new(ledger, clock, 100_000).unwrap()
    })
    .await
    .unwrap()
}

fn status(
    pseudonym: &cpsd::Pseudonym,
    device: &SigningKey,
    policy_epoch: u64,
) -> AccountServiceRequest {
    // Authentic Policy COSE at Balance's admission trust port;
    // production Policy grant issuance is a separately required owner seam.
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut grant = AdmissionGrant {
        version: 3,
        issuer_key_id: B64.encode(&Sha256::digest(issuer.verifying_key().to_bytes())),
        community_id: "example".into(),
        member_id: member_id(&pseudonym.to_bytes()),
        pseudonym: pseudonym.to_hex(),
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        policy_digest: B64.encode(&[4; 32]),
        policy_epoch,
        passport_policy_digest: B64.encode(&config(EXPIRY, EXPIRY).passport.digest()),
        issued_at: NOW,
        expires_at: NOW + 1800,
        signature: String::new(),
    };
    grant.signature = B64.encode(
        &policy_signer()
            .sign(
                csgn::Kind::Credential,
                &admission_bytes(&grant).unwrap(),
                grant.issued_at,
                grant.expires_at,
            )
            .unwrap(),
    );
    signed_status(grant, device)
}

fn signed_status(grant: AdmissionGrant, device: &SigningKey) -> AccountServiceRequest {
    let root = SigningKey::from_bytes(&[3; 32]);
    let mut authorization = DeviceAuthorization {
        version: 1,
        community_id: "example".into(),
        member_id: grant.member_id.clone(),
        root_public_key: B64.encode(&root.verifying_key().to_bytes()),
        device_public_key: grant.chat_public_key.clone(),
        issued_at: NOW,
        expires_at: NOW + 1800,
        signature: String::new(),
    };
    authorization.signature = B64.encode(
        &root
            .sign(&device_authorization_bytes(&authorization).unwrap())
            .to_bytes(),
    );
    let mut request = AccountStatusRequest {
        community: Sha256::digest(b"example").into(),
        owner: B64
            .decode(grant.member_id.as_bytes())
            .unwrap()
            .try_into()
            .unwrap(),
        request_id: None,
        challenge: [5; 32],
        chat_public_key: grant.chat_public_key.clone(),
        issued_at: NOW,
        expires_at: NOW + 60,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    AccountServiceRequest::Status {
        grant,
        authorization,
        request,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_policy_issues_the_grant_after_real_passport_and_passkey_admission() {
    use cmty::cgts::cblc::publication::PublicVerifierMaterial;
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let (trust, expected_epoch) = {
        let mut policy = f.engine.policy().lock().await;
        let fixture: serde_json::Value =
            serde_json::from_slice(include_bytes!("fixtures/balance-material.json")).unwrap();
        let mut material: PublicVerifierMaterial =
            serde_json::from_value(fixture["material"].clone()).unwrap();
        material.community = "example".into();
        material.policy = ledger_policy();
        material.policy_digest = material
            .policy
            .account
            .digest(&Sha256::digest(b"example").into())
            .unwrap();
        let version = policy.balance_version(NOW).await.unwrap();
        material.revision = version.revision;
        material.policy_epoch = version.epoch;
        // The status operation uses no extension proof. Do not attach an old
        // community's optional Wave verifier to this freshly projected policy.
        material.wave_verifier = None;
        let trust = AdmissionTrust {
            community_id: "example".into(),
            policy_digest: B64.encode(&material.policy_digest),
            policy_keys: policy.key_ring().unwrap().clone(),
        };
        policy.publish_balance(material, NOW).await.unwrap();
        (trust, version.epoch)
    };
    let original = service_with_trust(
        f.directory.path().join("issued-accounts"),
        || NOW,
        trust.clone(),
    )
    .await;
    f.engine = f.engine.with_account_service(original).await.unwrap();
    let (challenge, proof) = f.proof().await;
    let outcome = f
        .engine
        .finish_account_with(
            &mut f.rng,
            &challenge,
            &proof,
            AccountAdmission {
                membership: Admission {
                    authentication: &f.auth.authentication,
                    devices: &f.devices,
                    lease: crgs::YearMonth::new(2027, 9).unwrap(),
                },
                device: DEVICES[0],
            },
            NOW,
            async |_, _| Ok(Vec::new()),
        )
        .await
        .unwrap();
    let Outcome::Issued(issued) = outcome else {
        panic!("actual admitted credential")
    };
    let grant = issued.account.unwrap();
    verify_admission(&grant, &trust, NOW).unwrap();
    assert_eq!(grant.policy_epoch, expected_epoch);
    assert_eq!(grant.policy_epoch, issued.claims.policy_epoch);
    assert_eq!(
        grant.passport_policy_digest,
        B64.encode(&config(EXPIRY, EXPIRY).passport.digest())
    );
    assert_eq!(grant.pseudonym, f.passport.pseudonym(&scope()).to_hex());
    assert!(grant.expires_at <= issued.claims.valid_until);
    let wire = signed_status(grant, &SigningKey::from_bytes(&[13; 32]));
    let response = f
        .engine
        .account(&f.auth.authentication, wire.clone(), NOW)
        .await
        .unwrap();
    let (AccountServiceRequest::Status { request, .. }, AccountServiceResponse::Status(answer)) =
        (wire, response)
    else {
        panic!("signed status")
    };
    verify_account_status_response(
        &answer,
        &request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();

    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.engine
            .finish_account_with(
                &mut f.rng,
                &challenge,
                &proof,
                AccountAdmission {
                    membership: Admission {
                        authentication: &f.auth.authentication,
                        devices: &f.devices,
                        lease: crgs::YearMonth::new(2027, 9).unwrap(),
                    },
                    device: [99; 32],
                },
                NOW,
                async |_, _| Ok(Vec::new()),
            )
            .await,
        Err(Error::Signing)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn current_admitted_passkey_and_device_bind_every_forwarded_request() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let pseudonym = f.passport.pseudonym(&scope());
    let wire = status(
        &pseudonym,
        &SigningKey::from_bytes(&[13; 32]),
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch,
    );
    assert!(matches!(
        f.engine
            .account(&f.auth.authentication, wire.clone(), NOW)
            .await,
        Err(Error::Membership)
    ));
    assert!(matches!(f.issue().await, Outcome::Issued(_)));
    assert!(matches!(
        f.engine
            .account(&f.auth.authentication, wire.clone(), NOW)
            .await,
        Err(Error::AccountUnavailable)
    ));
    let time = f.clock.0.clone();
    let original = service(f.directory.path().join("accounts"), move || {
        time.load(Ordering::SeqCst) as u64
    })
    .await;
    f.engine = f.engine.with_account_service(original).await.unwrap();
    let answer = f
        .engine
        .account(&f.auth.authentication, wire.clone(), NOW)
        .await
        .unwrap();
    let AccountServiceResponse::Status(answer) = answer else {
        panic!("status response")
    };
    let AccountServiceRequest::Status { request, .. } = &wire else {
        unreachable!()
    };
    verify_account_status_response(
        &answer,
        request,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(answer.acceptance.is_none());
    let unbound = status(
        &pseudonym,
        &SigningKey::from_bytes(&[14; 32]),
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch,
    );
    assert!(matches!(
        f.engine.account(&f.auth.authentication, unbound, NOW).await,
        Err(Error::Membership)
    ));
    let other = cpsd::HolderSecret::generate(&mut rand::rngs::OsRng).pseudonym(&scope());
    assert!(matches!(
        f.engine
            .account(
                &f.auth.authentication,
                status(
                    &other,
                    &SigningKey::from_bytes(&[13; 32]),
                    f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch
                ),
                NOW
            )
            .await,
        Err(Error::Membership)
    ));
    let mut too_long = wire.clone();
    if let AccountServiceRequest::Status { ref mut grant, .. } = too_long {
        grant.expires_at = EXPIRY + 1;
    }
    assert!(matches!(
        f.engine
            .account(&f.auth.authentication, too_long, NOW)
            .await,
        Err(Error::Membership)
    ));
    f.engine
        .membership()
        .revoke_passkey(&f.auth.authentication, f.credential_id.clone())
        .await
        .unwrap();
    assert!(matches!(
        f.engine.account(&f.auth.authentication, wire, NOW).await,
        Err(Error::Membership)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authentic_old_grant_is_refused_after_the_community_epoch_advances() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(f.issue().await, Outcome::Issued(_)));
    let wire = status(
        &f.passport.pseudonym(&scope()),
        &SigningKey::from_bytes(&[13; 32]),
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch,
    );
    assert!(matches!(
        f.engine
            .account(&f.auth.authentication, wire.clone(), NOW)
            .await,
        Err(Error::AccountUnavailable)
    ));
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    assert!(matches!(
        f.engine.account(&f.auth.authentication, wire, NOW).await,
        Err(Error::Membership)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authentic_old_grant_is_refused_after_any_global_cohort_change() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(f.issue().await, Outcome::Issued(_)));
    let wire = status(
        &f.passport.pseudonym(&scope()),
        &SigningKey::from_bytes(&[13; 32]),
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch,
    );
    assert!(matches!(
        f.engine
            .account(&f.auth.authentication, wire.clone(), NOW)
            .await,
        Err(Error::AccountUnavailable)
    ));
    for case in 0..3 {
        let mut cohort = config(EXPIRY, EXPIRY).passport;
        match case {
            0 => cohort.valid_until += 86_400,
            1 => {
                cohort
                    .gates
                    .insert(cpsd::GateId::new("another-gate").unwrap());
            }
            2 => cohort.epoch += 1,
            _ => unreachable!(),
        }
        f.engine
            .refresh_passport_policy(cohort, EXPIRY, NOW)
            .await
            .unwrap();
        assert!(matches!(
            f.engine
                .account(&f.auth.authentication, wire.clone(), NOW)
                .await,
            Err(Error::Membership)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_the_caller_keeps_both_original_owner_leases_until_completion() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(f.issue().await, Outcome::Issued(_)));
    let wire = status(
        &f.passport.pseudonym(&scope()),
        &SigningKey::from_bytes(&[13; 32]),
        f.engine.snapshot(NOW).await.unwrap().rules.policy_epoch,
    );
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = AtomicBool::new(true);
    let time = f.clock.0.clone();
    let original = service(f.directory.path().join("accounts"), move || {
        if first.swap(false, Ordering::SeqCst) {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(30)).unwrap();
        }
        time.load(Ordering::SeqCst) as u64
    })
    .await;
    let engine = Arc::new(f.engine.with_account_service(original).await.unwrap());
    let caller = engine.clone();
    let authentication = f.auth.authentication.clone();
    let task = tokio::spawn(async move { caller.account(&authentication, wire, NOW).await });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(engine.policy().try_lock().is_err());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            engine
                .membership()
                .current_device_keys(&f.auth.authentication)
        )
        .await
        .is_err()
    );
    release.send(()).unwrap();
    let policy = tokio::time::timeout(Duration::from_secs(30), engine.policy().lock())
        .await
        .unwrap();
    drop(policy);
    assert_eq!(
        engine
            .membership()
            .current_device_keys(&f.auth.authentication)
            .await
            .unwrap(),
        DEVICES
    );
}
