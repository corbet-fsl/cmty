//! Genuine G1 admission and original Policy grant projection/currentness checks.
//! These tests do not install a native account service or claim proof acceptance.
mod support;
use cmty::{
    cgts::cblc::{accounting::*, accounting_ledger::*, accounting_service::*, admission::*},
    *,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use support::*;

// The fixture host's actual clock and exclusive session lifetime. These owner
// boundary tests install no native service and cannot authorize a proof.
struct Session(Clock);
impl AccountSession for Session {
    fn valid_until(&self) -> u64 {
        EXPIRY
    }
    fn check(&self, observed: u64) -> cmty::Result<()> {
        if clbs::Clock::now(&self.0)
            .ok()
            .and_then(|now| u64::try_from(now).ok())
            == Some(observed)
            && observed < EXPIRY
        {
            Ok(())
        } else {
            Err(Error::Time)
        }
    }
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

#[test]
fn original_signed_v1_material_cannot_fill_required_admission_digest() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material.json")).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let bytes: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let signed = ring
        .verify(&bytes, csgn::Kind::SettingsSnapshot, 200)
        .unwrap();
    assert!(serde_json::from_slice::<cplc::PublicVerifierMaterial>(signed.payload()).is_err());
}

async fn publish_original_balance(f: &Fixture<cmty::storage::LibsqlStorage>) -> AdmissionTrust {
    let mut policy = f.engine.policy().lock().await;
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material-v2.json")).unwrap();
    let mut material: cplc::PublicVerifierMaterial =
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
    let trust = AdmissionTrust {
        community_id: "example".into(),
        // Independent immutable admission configuration of the native producer.
        policy_digest: B64.encode(&[3; 32]),
        policy_keys: policy.key_ring().unwrap().clone(),
    };
    policy.publish_balance(material, NOW).await.unwrap();
    trust
}

async fn issue_account(
    f: &mut Fixture<cmty::storage::LibsqlStorage>,
    device: [u8; 32],
) -> cmty::Result<Outcome> {
    let (challenge, proof) = f.proof().await;
    f.engine
        .finish_account_with(
            &mut f.rng,
            &challenge,
            &proof,
            AccountAdmission {
                membership: Admission {
                    authentication: &f.auth.authentication,
                    devices: &DEVICES,
                    lease: crgs::YearMonth::new(2027, 9).unwrap(),
                },
                device,
            },
            NOW,
            async |_, _| Ok(Vec::new()),
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn real_passport_member_policy_and_device_project_the_same_bound_grant() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let ordinary = f.issue().await;
    let Outcome::Issued(ordinary) = ordinary else {
        panic!("real ordinary credential")
    };
    assert!(ordinary.account.is_none());
    let trust = publish_original_balance(&f).await;
    let outcome = issue_account(&mut f, DEVICES[0]).await.unwrap();
    let Outcome::Issued(issued) = outcome else {
        panic!("actual admitted credential")
    };
    let grant = issued.account.unwrap();
    verify_admission(&grant, &trust, NOW).unwrap();
    assert_eq!(grant.policy_epoch, issued.claims.policy_epoch);
    assert_eq!(
        grant.passport_policy_digest,
        B64.encode(&config(EXPIRY, EXPIRY).passport.digest())
    );
    assert_eq!(grant.pseudonym, f.passport.pseudonym(&scope()).to_hex());
    assert_eq!(grant.chat_public_key, B64.encode(&DEVICES[0]));
    assert!(grant.expires_at <= issued.claims.valid_until);
    assert!(matches!(
        issue_account(&mut f, [99; 32]).await,
        Err(Error::Reconcile)
    ));
    let wire = signed_status(grant, &SigningKey::from_bytes(&[13; 32]));
    let auth = Arc::new(f.auth.authentication);
    let session: Arc<dyn AccountSession> = Arc::new(Session(f.clock.clone()));
    assert!(matches!(
        f.engine
            .account(auth.clone(), wire.clone(), NOW, session.clone())
            .await,
        Err(Error::AccountUnavailable)
    ));
    // Independent original host checks run before the missing service boundary.
    for field in 0..6 {
        let mut changed = wire.clone();
        let AccountServiceRequest::Status { ref mut grant, .. } = changed else {
            unreachable!()
        };
        match field {
            0 => grant.policy_epoch += 1,
            1 => grant.passport_policy_digest = B64.encode(&[90; 32]),
            2 => grant.chat_public_key = B64.encode(&[91; 32]),
            3 => grant.expires_at = NOW,
            4 => grant.pseudonym = "ab".repeat(48),
            _ => grant.community_id = "another.community".into(),
        }
        assert!(matches!(
            f.engine
                .account(auth.clone(), changed, NOW, session.clone())
                .await,
            Err(Error::Membership)
        ));
    }
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    assert!(matches!(
        f.engine.account(auth, wire, NOW, session).await,
        Err(Error::Membership)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn requested_account_flow_refuses_unconfigured_balance_without_fabricating_a_grant() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(
        issue_account(&mut f, DEVICES[0]).await,
        Err(Error::Reconcile)
    ));
    // Missing Balance was discovered after successful actual admission. The
    // original member row persists; no no-effect response is manufactured.
    assert_eq!(
        f.engine
            .membership()
            .resume(&f.auth.authentication)
            .await
            .unwrap()
            .state(),
        cnrl::State::Admitted
    );
}

#[test]
fn original_cohort_digest_commits_epoch_expiry_and_the_entire_sorted_gate_set() {
    let policy = config(EXPIRY, EXPIRY).passport;
    let digest = policy.digest();
    for field in 0..3 {
        let mut changed = policy.clone();
        match field {
            0 => changed.epoch += 1,
            1 => changed.valid_until += 86_400,
            _ => {
                changed
                    .gates
                    .insert(cpsd::GateId::new("another-gate").unwrap());
            }
        }
        assert_ne!(changed.digest(), digest);
    }
    // Independently encode the original transcript; no policy-derived period or
    // global claim list is inserted into the public account grant.
    let mut bytes = b"cmty.passport-policy.v1\0".to_vec();
    bytes.extend_from_slice(&policy.epoch.to_be_bytes());
    bytes.extend_from_slice(&policy.valid_until.to_be_bytes());
    bytes.extend_from_slice(&(policy.gates.len() as u64).to_be_bytes());
    for gate in &policy.gates {
        bytes.extend_from_slice(&(gate.as_str().len() as u64).to_be_bytes());
        bytes.extend_from_slice(gate.as_str().as_bytes());
    }
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(bytes)));
}

#[tokio::test(flavor = "multi_thread")]
async fn host_publication_requires_configured_period_and_the_actual_native_owner() {
    const KEY: &str = "record/window";
    let f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(
        f.engine.publish_account_record(KEY, || NOW).await,
        Err(Error::Policy)
    ));
    let mut rules = f.rules.clone();
    crbk::RecordEpochSettings::define(&mut rules, KEY).unwrap();
    rules
        .set_community(KEY, Some(serde_json::json!(100)))
        .unwrap();
    f.engine
        .policy()
        .lock()
        .await
        .schedule_rules(
            Some(1),
            crbk::Change {
                rulebook: rules,
                announced_at: NOW as i64,
                effective_at: NOW as i64,
                notice_seconds: 0,
                policy_epoch: 2,
            },
        )
        .await
        .unwrap();
    // Neither bootstrap nor full G2 material can be manufactured without the
    // installed original native service; no synthetic empty descriptor escapes.
    assert!(matches!(
        f.engine.publish_account_material(KEY, || NOW).await,
        Err(Error::AccountUnavailable)
    ));
    assert!(matches!(
        f.engine.publish_account_record(KEY, || NOW).await,
        Err(Error::AccountUnavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn trusted_waiting_tuning_refuses_without_the_same_account_owner() {
    let f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(
        f.engine.tune_account_waiting_period(0, 100, || NOW).await,
        Err(Error::AccountUnavailable)
    ));
    assert!(matches!(
        f.engine.tune_account_waiting_period(0, 100, || 0).await,
        Err(Error::Time)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_policy_ring_cannot_substitute_a_missing_native_owner() {
    let f = fixture(EXPIRY, EXPIRY).await;
    assert!(matches!(
        f.engine.reconcile_account_admission_keys(|| NOW).await,
        Err(Error::AccountUnavailable)
    ));
    assert!(matches!(
        f.engine.reconcile_account_admission_keys(|| 0).await,
        Err(Error::Time)
    ));
}
