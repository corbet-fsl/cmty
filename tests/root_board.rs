//! Root admission through real CPSD blind issuance, durable challenge storage,
//! passkeys, Membership, Gatekeeping and Policy. No synthetic admitted row.
mod support;

use cmty::*;
use cpsd::{
    rand::{SeedableRng, rngs::StdRng},
    *,
};
use std::sync::{Arc, atomic::AtomicI64};
use support::{Clock, DEVICES, EXPIRY, Engine, NOW, ORIGIN, USER};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

// Exercise the credential cap near the end of a common root cohort, while the
// global passport remains valid for several more weeks.
const AT: u64 = (NOW / ROOT_BOARD_COHORT_SECONDS + 1) * ROOT_BOARD_COHORT_SECONDS - 600;

struct Root {
    _directory: tempfile::TempDir,
    engine: Engine<cmty::storage::LibsqlStorage>,
    holder: OpaqueHolder,
    expected: AuthenticatedCommunity,
    descriptor: RootBoardPublicKey,
    rng: StdRng,
}

fn rules() -> crbk::Rulebook {
    let mut rules = crbk::Rulebook::default();
    for key in [
        crbk::gate_key(crbk::GateLevel::Global, "global-test"),
        crbk::provider_key(crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
    ] {
        rules
            .define(
                key,
                crbk::Setting {
                    value_type: crbk::SettingType::Boolean,
                    nullable: false,
                    default: true.into(),
                    bounds: crbk::Bounds::default(),
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
    }
    rules
        .define(
            crbk::action_key(ADMISSION_ACTION),
            crbk::Setting {
                value_type: crbk::SettingType::Policy,
                nullable: true,
                default: serde_json::to_value(crbk::ActionPolicy {
                    all_of: vec![crbk::Requirement {
                        gate: "global-test".into(),
                        level: crbk::GateLevel::Global,
                        provider: None,
                    }],
                    ..Default::default()
                })
                .unwrap(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    rules
}

async fn root() -> Root {
    let directory = tempfile::tempdir().unwrap();
    let db = support::open(
        &format!("file://{}", directory.path().join("root.db").display()),
        "",
    )
    .await;
    let scope = CommunityId::new("root").unwrap();
    let source = CommunityId::new("source").unwrap();
    let gate = GateId::new("global-test").unwrap();
    let mut rng = StdRng::seed_from_u64(1701);
    let global =
        IssuerKey::generate(&mut rng, KeyId::new("global").unwrap(), vec![gate.clone()]).unwrap();
    let common = IssuerKey::generate(
        &mut rng,
        KeyId::new("common-root").unwrap(),
        vec![GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let mut holder =
        OpaqueHolder::from_seed_and_sealing_key(&mut [17; 32], &mut [18; 32], b"root-test")
            .unwrap();
    let challenge = IssuanceChallenge::generate(&mut rng);
    let request = holder
        .begin_issuance(&mut rng, global.public_key(), &challenge)
        .unwrap();
    let blind = global
        .issue_blind(
            &mut rng,
            &request,
            &challenge,
            &PassportAttributes::new(EXPIRY, 7).with_gate(gate.clone(), EXPIRY),
        )
        .unwrap();
    holder.finish_issuance(&blind).unwrap();

    let (mut policy, _) = support::policies_in(&db, rules(), "root").await;
    let descriptor = RootBoardPublicKey::from_authenticated_beacon(
        common.public_key().clone(),
        scope.clone(),
        policy.epoch(AT).await.unwrap(),
        AT / ROOT_BOARD_COHORT_SECONDS * ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    policy.publish_root_board(&descriptor, AT).await.unwrap();
    let expected = AuthenticatedCommunity::from_authenticated_origin(
        scope.clone(),
        policy.key_ring().unwrap().clone(),
    );
    let mut source_signer = csgn::Signer::new(
        "source",
        csgn::SecretKey::from_seed(&mut [19; 32]),
        NOW,
        EXPIRY - NOW,
    )
    .unwrap();
    let expected_source = AuthenticatedCommunity::from_authenticated_origin(
        source.clone(),
        source_signer.key_ring().clone(),
    );
    let context = RootBoardIssuanceContext::new(
        &mut rng,
        PresentationRequest::for_epoch(
            &mut StdRng::seed_from_u64(1702),
            source,
            7,
            [gate],
            AT + 60,
            EXPIRY,
        )
        .unwrap(),
        descriptor.clone(),
    )
    .unwrap();
    let signed = policy
        .sign_root_board_issuance_context(&context, AT)
        .await
        .unwrap();
    let signed_source = source_signer
        .sign(
            csgn::Kind::Credential,
            &context.source_request().to_bytes(),
            AT,
            AT + 61,
        )
        .unwrap();
    let issuance = holder
        .begin_root_board_issuance(
            &mut rng,
            &expected,
            &signed,
            &expected_source,
            &signed_source,
            AT,
        )
        .unwrap();
    let verified =
        verify_root_board_issuance(&[global.public_key().clone()], &context, &issuance, AT)
            .unwrap();
    // This fixture supplies a real credential from its issuer; authorization of
    // the source role belongs to the separate issuance-service tests.
    let blind = issue_blind_root_board(&mut rng, &common, &descriptor, verified, AT).unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    let engine = Community::new_root_board(
        cmty::storage::LibsqlStorage::new(&db, scope, 32).unwrap(),
        vec![global.public_key().clone()],
        Parts {
            membership: support::members_in(
                &db,
                Clock(Arc::new(AtomicI64::new(AT as i64))),
                "root",
            ),
            gates: support::gates_in(&db, "root"),
            policy,
        },
        support::config(EXPIRY, EXPIRY),
    )
    .unwrap();
    Root {
        _directory: directory,
        engine,
        holder,
        expected,
        descriptor,
        rng,
    }
}

impl Root {
    async fn proof(&mut self) -> (Challenge, RootBoardPresentation) {
        let challenge = self.engine.begin(&mut self.rng, AT).await.unwrap();
        assert!(challenge.root_board_request().unwrap().root() == &self.descriptor);
        let proof = self
            .holder
            .present_root_board(
                &mut self.rng,
                &self.expected,
                challenge.signed_request(),
                AT,
            )
            .unwrap();
        (challenge, proof)
    }

    async fn enrol(&mut self) -> cmbr::Login {
        let (challenge, proof) = self.proof().await;
        let verified = self
            .engine
            .verify_root_board(&challenge, &proof, AT)
            .await
            .unwrap();
        assert_eq!(
            verified.member_id(),
            self.holder.pseudonym(self.engine.community()).to_hex()
        );
        let (request, pending) = self
            .engine
            .begin_registration(verified, USER, AT)
            .await
            .unwrap();
        let mut device = SoftToken::new(true).unwrap().0;
        let mut options = request.public_key;
        options
            .authenticator_selection
            .as_mut()
            .unwrap()
            .require_resident_key = false;
        let response = device
            .perform_register(ckyh::Url::parse(ORIGIN).unwrap(), options, 300_000)
            .unwrap();
        let credential: ckyh::CredentialID = response.raw_id.clone().into();
        self.engine
            .membership()
            .finish_registration(pending, response.into())
            .await
            .unwrap();
        let (request, pending) = self
            .engine
            .membership()
            .begin_login(USER, credential)
            .await
            .unwrap();
        let response = device
            .perform_auth(
                ckyh::Url::parse(ORIGIN).unwrap(),
                request.public_key,
                300_000,
            )
            .unwrap();
        let login = self
            .engine
            .membership()
            .finish_login(pending, response.into())
            .await
            .unwrap();
        self.engine
            .membership()
            .authorize_device_key(&login.authentication, DEVICES[0])
            .await
            .unwrap();
        self.engine
            .membership()
            .reserve_handle(&login.authentication, "root_member", &[])
            .await
            .unwrap();
        login
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn joint_registration_and_renewal_issue_ordinary_membership_bounded_by_root_expiry() {
    let mut f = root().await;
    let login = f.enrol().await;
    for _ in 0..2 {
        let (challenge, proof) = f.proof().await;
        let outcome = f
            .engine
            .finish_root_board_with(
                &challenge,
                &proof,
                Admission {
                    authentication: &login.authentication,
                    devices: &DEVICES,
                    lease: crgs::YearMonth::new(2027, 9).unwrap(),
                },
                AT,
                async |_, _| Ok(Vec::new()),
            )
            .await
            .unwrap();
        let Outcome::Issued(issued) = outcome else {
            panic!("expected real root membership credential")
        };
        assert_eq!(issued.claims.community, "root");
        assert_eq!(
            issued.claims.member_id,
            f.holder.pseudonym(f.engine.community()).to_hex()
        );
        assert_eq!(issued.claims.valid_until, f.descriptor.expires_at());
        assert!(issued.claims.gates.is_empty());
        let snapshot = f.engine.snapshot(AT).await.unwrap();
        let verified = snapshot
            .signing_keys
            .verify(&issued.cose, csgn::Kind::Credential, AT)
            .unwrap();
        let payload: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(payload, issued.claims.payload().unwrap());
        let text = String::from_utf8(verified.payload().to_vec()).unwrap();
        for hidden in ["source", "root-board", "role", "global-test"] {
            assert!(!text.contains(hidden));
        }
        assert_eq!(
            f.engine
                .membership()
                .resume(&login.authentication)
                .await
                .unwrap()
                .state(),
            cnrl::State::Admitted
        );
        assert!(
            f.engine
                .verify_root_board(&challenge, &proof, AT)
                .await
                .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_passport_cannot_downgrade_root_challenge_or_consume_its_joint_slot() {
    let mut f = root().await;
    let (challenge, joint) = f.proof().await;
    let signed_ordinary = f
        .engine
        .policy()
        .lock()
        .await
        .sign_presentation_request(challenge.request(), AT)
        .await
        .unwrap();
    let ordinary = f
        .holder
        .present(&mut f.rng, &f.expected, &signed_ordinary, AT)
        .unwrap();
    assert!(matches!(
        f.engine.verify(&mut f.rng, &challenge, &ordinary, AT).await,
        Err(cmty::Error::Passport)
    ));
    assert!(
        f.engine
            .verify_root_board(&challenge, &joint, AT)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_change_refuses_retained_joint_proof_and_previously_verified_registration() {
    let mut f = root().await;
    let (first, first_proof) = f.proof().await;
    let verified = f
        .engine
        .verify_root_board(&first, &first_proof, AT)
        .await
        .unwrap();
    let (second, second_proof) = f.proof().await;
    f.engine.policy().lock().await.bump_epoch().await.unwrap();
    assert!(matches!(
        f.engine.verify_root_board(&second, &second_proof, AT).await,
        Err(cmty::Error::Policy)
    ));
    assert!(matches!(
        f.engine.begin_registration(verified, USER, AT).await,
        Err(cmty::Error::Policy)
    ));
    assert!(f.engine.begin(&mut f.rng, AT).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn reserved_root_scope_requires_the_explicit_root_constructor() {
    for (community, root_mode) in [("root", false), ("example", true)] {
        let directory = tempfile::tempdir().unwrap();
        let db = support::open(
            &format!("file://{}", directory.path().join("scope.db").display()),
            "",
        )
        .await;
        let (policy, _) = support::policies_in(&db, rules(), community).await;
        let mut rng = StdRng::seed_from_u64(1710);
        let issuer = IssuerKey::generate(
            &mut rng,
            KeyId::new("global").unwrap(),
            vec![GateId::new("global-test").unwrap()],
        )
        .unwrap();
        let storage =
            cmty::storage::LibsqlStorage::new(&db, CommunityId::new(community).unwrap(), 8)
                .unwrap();
        let parts = Parts {
            membership: support::members_in(
                &db,
                Clock(Arc::new(AtomicI64::new(AT as i64))),
                community,
            ),
            gates: support::gates_in(&db, community),
            policy,
        };
        let engine = if root_mode {
            Community::new_root_board(
                storage,
                vec![issuer.public_key().clone()],
                parts,
                support::config(EXPIRY, EXPIRY),
            )
        } else {
            Community::new(
                storage,
                vec![issuer.public_key().clone()],
                parts,
                support::config(EXPIRY, EXPIRY),
            )
        };
        assert!(matches!(engine, Err(cmty::Error::Scope)));
    }
}
