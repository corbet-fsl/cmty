//! Root admission through real CPSD blind issuance, durable challenge storage,
//! passkeys, Membership, Gatekeeping and Policy. No synthetic admitted row.
#[path = "root_board/creation.rs"]
mod creation;
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
    let scope = CommunityId::new("adminboard").unwrap();
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
    let (mut policy, _) = support::policies_in(&db, rules(), "adminboard").await;
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
    let holder = creation::holder(
        &mut rng,
        &global,
        &common,
        &mut policy,
        &descriptor,
        &expected,
        17,
    )
    .await;
    let first_root = creation::holder(
        &mut rng,
        &global,
        &common,
        &mut policy,
        &descriptor,
        &expected,
        27,
    )
    .await;
    assert_ne!(
        holder.pseudonym(&scope).to_hex(),
        first_root.pseudonym(&scope).to_hex(),
    );
    let engine = Community::new_root_board(
        cmty::storage::LibsqlStorage::new(&db, scope, 32).unwrap(),
        vec![global.public_key().clone()],
        Parts {
            membership: support::members_in(
                &db,
                Clock(Arc::new(AtomicI64::new(AT as i64))),
                "adminboard",
            ),
            gates: support::gates_in(&db, "adminboard"),
            policy,
        },
        support::config(EXPIRY, EXPIRY),
    )
    .unwrap();
    let mut fixture = Root {
        _directory: directory,
        engine,
        holder,
        expected,
        descriptor,
        rng,
    };
    creation::bootstrap(&mut fixture, &first_root).await;
    fixture
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
        creation::enrol(
            &self.engine,
            &self.holder,
            &self.expected,
            &mut self.rng,
            USER,
            "root_member",
            DEVICES[0],
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn joint_registration_and_renewal_issue_ordinary_membership_bounded_by_root_expiry() {
    let mut f = root().await;
    let login = f.enrol().await;
    let session = support::Session::new(&login.authentication, f.descriptor.expires_at());
    for _ in 0..2 {
        let (challenge, proof) = f.proof().await;
        let outcome = f
            .engine
            .finish_root_board_with(
                &challenge,
                &proof,
                Admission {
                    authentication: &login.authentication,
                    session: &session,
                    creation: None,
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
        assert_eq!(issued.claims.community, "adminboard");
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
        assert_eq!(
            f.engine
                .membership()
                .member(&login.authentication)
                .await
                .unwrap()
                .unwrap()
                .role,
            crgs::Role::Member,
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
async fn the_board_is_selected_by_the_constructor_never_by_the_community_name() {
    // A community NAMED root is an ordinary community; the board may carry any ordinary name.
    for (community, root_mode) in [("root", false), ("example", true), ("adminboard", true)] {
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
        assert!(engine.is_ok(), "{community} board={root_mode}");
    }
}
