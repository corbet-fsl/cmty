use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use cmty::{
    adapters::SharedRulebook,
    storage::{self, Storage},
    *,
};
use cpsd::{
    rand::{SeedableRng, rngs::StdRng},
    *,
};
use ed25519_dalek::{Signer, SigningKey};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const NOW: u64 = 1_800_000_000 / 86_400 * 86_400;
pub const EXPIRY: u64 = NOW + 90 * 86_400;
pub const USER: ckyh::Uuid = ckyh::Uuid::from_u128(1);
pub const ORIGIN: &str = "https://members.example.org";
// Ed25519 public key of the fixture seed [13; 32], checked at setup below.
pub const DEVICES: [[u8; 32]; 1] = [[
    145, 162, 138, 11, 116, 56, 21, 147, 164, 217, 70, 149, 121, 32, 137, 38, 175, 200, 173, 130,
    200, 131, 155, 118, 68, 53, 155, 158, 186, 154, 75, 58,
]];

pub fn scope() -> CommunityId {
    CommunityId::new("example").unwrap()
}

#[derive(Clone)]
pub struct Clock(pub Arc<AtomicI64>);
impl clbs::Clock for Clock {
    fn now(&self) -> clbs::Result<i64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

// Real signature verification at the external qualified-authority boundary.
#[derive(Clone)]
pub struct Authority;
impl clbs::Verifier for Authority {
    async fn verify_legal(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        let signature =
            ed25519_dalek::Signature::from_slice(&order.proof).map_err(|_| clbs::Error::Denied)?;
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify_strict(&order.order.signing_payload()?, &signature)
            .map_err(|_| clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}

// Development-only provider; production exports no always-pass gate.
pub struct DevelopmentGate {
    pub until: i64,
    pub transient: bool,
    pub fail: bool,
}
impl cgts::Gate for DevelopmentGate {
    type Input = ();
    fn descriptor(&self) -> cgts::Descriptor {
        cgts::Descriptor {
            gate: "dev-test".into(),
            provider: "test-only".into(),
            level: crbk::GateLevel::Community,
            steps: vec![cgts::Step {
                id: "fixture".into(),
                description: "Synthetic fixture".into(),
                input: "unit".into(),
            }],
        }
    }
    async fn verify(&self, _: cgts::Context<'_>, _: &()) -> cgts::Result<cgts::Proof> {
        if self.fail {
            return Err(cgts::Error::Refused);
        }
        Ok(if self.transient {
            cgts::Proof::transient(self.until)
        } else {
            cgts::Proof::retained(self.until)
        })
    }
}

type Members = cmbr::Membership<cmbr::LibsqlStorage, Authority, Clock>;
type Gates = cgts::Gatekeeper<cgts::LibsqlStore, cgts::LegalGate<clbs::LibsqlStore, Authority>>;
type Rules = SharedRulebook<crbk::LibsqlStore>;
type Policies = cplc::Policy<Rules, cplc::LibsqlStore, csgn::LibsqlStore>;
pub type Engine<S> = Community<
    S,
    cmbr::LibsqlStorage,
    Authority,
    Clock,
    cgts::LibsqlStore,
    cgts::LegalGate<clbs::LibsqlStore, Authority>,
    Rules,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;

pub struct Fixture<S: Storage> {
    pub engine: Engine<S>,
    pub passport: Passport,
    pub rng: StdRng,
    pub db: crlt::Db,
    pub auth: cmbr::Login,
    pub clock: Clock,
    pub credential_id: ckyh::CredentialID,
    pub devices: Vec<[u8; 32]>,
    pub rules: crbk::Rulebook,
    pub fingerprint: [u8; 32],
    pub config_until: u64,
    pub directory: tempfile::TempDir,
}

pub fn migrations() -> Vec<crlt::Migration<'static>> {
    let mut schemas = cmbr::SCHEMAS.to_vec();
    schemas.extend([
        ("cgts", cgts::SCHEMA),
        ("crbk", crbk::SCHEMA),
        ("cplc", cplc::SCHEMA),
        ("csgn", csgn::SCHEMA),
        ("cpsd", storage::SCHEMA),
        ("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA),
    ]);
    schemas
        .into_iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect()
}

pub async fn open(url: &str, token: &str) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    let migrations = migrations();
    db.migrate(&migrations).await.unwrap();
    assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
    db
}

pub fn members(db: &crlt::Db, clock: Clock) -> Members {
    cmbr::Membership::new(
        db,
        cmbr::LibsqlStorage::new(db, "example").unwrap(),
        cmbr::Config {
            pending_days: 2,
            lease_months: 12,
            membership_action: ADMISSION_ACTION.into(),
            release_period: crgs::ReleasePeriod::default(),
            rp_id: "members.example.org".into(),
            origins: vec![ckyh::Url::parse(ORIGIN).unwrap()],
        },
        Authority,
        clock,
    )
    .unwrap()
}

pub fn gates(db: &crlt::Db) -> Gates {
    cgts::Gatekeeper::new(
        cgts::LibsqlStore::new(db, "example").unwrap(),
        cgts::LegalGate::new(clbs::LibsqlStore::new(db, "example").unwrap(), Authority),
    )
    .unwrap()
}

pub fn config(expiry: u64, valid_until: u64) -> Config {
    Config {
        passport: PassportPolicy {
            epoch: 7,
            valid_until: expiry,
            gates: [GateId::new("global-test").unwrap()].into(),
        },
        valid_until,
        challenge_lifetime: 60,
    }
}

pub fn rulebook() -> crbk::Rulebook {
    let mut rules = crbk::Rulebook::default();
    for (level, name, provider) in [
        (crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
        (crbk::GateLevel::Community, "dev-test", "test-only"),
    ] {
        for key in [
            crbk::gate_key(level, name),
            crbk::provider_key(level, name, provider),
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
    }
    rules
        .define(
            crbk::action_key(ADMISSION_ACTION),
            crbk::Setting {
                value_type: crbk::SettingType::Policy,
                nullable: true,
                default: serde_json::to_value(crbk::ActionPolicy {
                    all_of: vec![
                        crbk::Requirement {
                            gate: "global-test".into(),
                            level: crbk::GateLevel::Global,
                            provider: None,
                        },
                        crbk::Requirement {
                            gate: "dev-test".into(),
                            level: crbk::GateLevel::Community,
                            provider: None,
                        },
                    ],
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

pub fn schema(version: u32) -> cplc::cshm::Schema {
    serde_json::from_value(serde_json::json!({ "community":"example", "version":version,
        "public":[{"id":"restricted-field","label":"Restricted field", "kind":{"type":"yes_no"},
        "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}], "private":[] })).unwrap()
}

pub async fn policies(db: &crlt::Db, rules: crbk::Rulebook) -> (Policies, Rules) {
    let store = SharedRulebook::new(crbk::LibsqlStore::new(db.clone()));
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
        store.clone(),
        cplc::LibsqlStore::new(db, "example").unwrap(),
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
                rulebook: rules,
                announced_at: NOW as i64,
                effective_at: NOW as i64,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    policy.set_schema(schema(3)).await.unwrap();
    (policy, store)
}

pub async fn passport(rng: &mut StdRng, expiry: u64) -> Passport {
    let gate = GateId::new("global-test").unwrap();
    let issuer = IssuerKey::generate(
        rng,
        KeyId::new("shared-issuer").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let secret = HolderSecret::generate(rng);
    blind_passport(rng, &issuer, &secret, gate, expiry, 7).await
}

pub async fn blind_passport(
    rng: &mut StdRng,
    issuer: &IssuerKey,
    secret: &HolderSecret,
    gate: GateId,
    expiry: u64,
    epoch: u64,
) -> Passport {
    let store = cpsd::MemoryStore::new(CommunityId::new("issuer").unwrap(), 10).unwrap();
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let challenge = issuance_challenge(rng, &store, issuer.public_key(), &auth, NOW + 60)
        .await
        .unwrap();
    let (request, pending) = request_issue(rng, secret, issuer.public_key(), &challenge).unwrap();
    let blind = issue_blind_once(
        rng,
        &store,
        issuer,
        &auth,
        &request,
        &challenge,
        &PassportAttributes::new(expiry, epoch).with_gate(gate, expiry),
        NOW,
    )
    .await
    .unwrap();
    pending.finish(&blind).unwrap()
}

pub async fn fixture(expiry: u64, valid_until: u64) -> Fixture<storage::LibsqlStorage> {
    fixture_with(expiry, valid_until, |db| {
        storage::LibsqlStorage::new(db, scope(), 32).unwrap()
    })
    .await
}

pub async fn fixture_with<S: Storage>(
    expiry: u64,
    valid_until: u64,
    storage: impl FnOnce(&crlt::Db) -> S,
) -> Fixture<S> {
    fixture_with_identity(expiry, valid_until, storage, None, 7).await
}

pub async fn fixture_with_identity<S: Storage>(
    expiry: u64,
    valid_until: u64,
    storage: impl FnOnce(&crlt::Db) -> S,
    identity: Option<Passport>,
    epoch: u64,
) -> Fixture<S> {
    let directory = tempfile::tempdir().unwrap();
    let db = open(
        &format!("file://{}", directory.path().join("community.db").display()),
        "",
    )
    .await;
    let clock = Clock(Arc::new(AtomicI64::new(NOW as i64)));
    let mut rng = StdRng::seed_from_u64(42);
    let passport = match identity {
        Some(passport) => passport,
        None => passport(&mut rng, expiry).await,
    };
    let rules = rulebook();
    let (policy, _) = policies(&db, rules.clone()).await;
    let mut configuration = config(expiry, valid_until);
    configuration.passport.epoch = epoch;
    let engine = Community::new(
        storage(&db),
        vec![passport.issuer().clone()],
        Parts {
            membership: members(&db, clock.clone()),
            gates: gates(&db),
            policy,
        },
        configuration,
    )
    .unwrap();
    let challenge = engine.begin(&mut rng, NOW).await.unwrap();
    let presentation = present(&engine, &passport, &mut rng, &challenge, NOW).await;
    let verified = engine
        .verify(&mut rng, &challenge, &presentation, NOW)
        .await
        .unwrap();
    assert_eq!(verified.member_id(), passport.pseudonym(&scope()).to_hex());
    let (request, pending) = engine
        .begin_registration(verified, USER, NOW)
        .await
        .unwrap();
    let mut device = SoftToken::new(true).unwrap().0;
    let response = device
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
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
    let (request, pending) = engine
        .membership()
        .begin_login(USER, credential_id.clone())
        .await
        .unwrap();
    let response = device
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            request.public_key,
            300_000,
        )
        .unwrap();
    let auth = engine
        .membership()
        .finish_login(pending, response.into())
        .await
        .unwrap();
    assert_eq!(
        DEVICES[0],
        SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes()
    );
    engine
        .membership()
        .authorize_device_key(&auth.authentication, DEVICES[0])
        .await
        .unwrap();
    engine
        .membership()
        .reserve_handle(&auth.authentication, "test_member", &[])
        .await
        .unwrap();
    let submission = cmbr::PinV2::seal(
        &cpns::FingerprintContext {
            community: "example",
            member: &passport.pseudonym(&scope()).to_hex(),
            field: "restricted-field",
        },
        b"true",
        &cpns::Salt::from_bytes(vec![11; 32]).unwrap(),
    );
    let fingerprint = *submission.fingerprint().as_bytes();
    engine
        .membership()
        .pin(&auth.authentication, "restricted-field", &submission)
        .await
        .unwrap();
    let f = Fixture {
        engine,
        passport,
        rng,
        db,
        auth,
        clock,
        credential_id,
        devices: DEVICES.to_vec(),
        rules,
        fingerprint,
        config_until: valid_until,
        directory,
    };
    f.gate(expiry as i64).await;
    f
}

impl<S: Storage> Fixture<S> {
    pub fn admission(&self) -> Admission<'_> {
        Admission {
            authentication: &self.auth.authentication,
            devices: &self.devices,
            lease: crgs::YearMonth::new(2027, 9).unwrap(),
        }
    }
    pub async fn proof(&mut self) -> (Challenge, Presentation) {
        let now = self.clock.0.load(Ordering::SeqCst) as u64;
        let challenge = self.engine.begin(&mut self.rng, now).await.unwrap();
        let proof = present(&self.engine, &self.passport, &mut self.rng, &challenge, now).await;
        (challenge, proof)
    }
    pub async fn finish(
        &mut self,
        challenge: &Challenge,
        proof: &Presentation,
        now: u64,
    ) -> cmty::Result<Outcome> {
        self.clock.0.store(now as i64, Ordering::SeqCst);
        self.engine
            .finish(
                &mut self.rng,
                challenge,
                proof,
                Admission {
                    authentication: &self.auth.authentication,
                    devices: &self.devices,
                    lease: crgs::YearMonth::new(2027, 9).unwrap(),
                },
                now,
            )
            .await
    }
    pub async fn issue(&mut self) -> Outcome {
        let (challenge, proof) = self.proof().await;
        let now = self.clock.0.load(Ordering::SeqCst) as u64;
        self.finish(&challenge, &proof, now).await.unwrap()
    }
    pub async fn gate(&self, until: i64) {
        let snapshot = self.engine.snapshot(NOW).await.unwrap();
        let subject = self.passport.pseudonym(&scope()).to_hex();
        self.engine
            .gates()
            .run(
                cgts::Context {
                    snapshot: &snapshot.rules,
                    subject: &subject,
                    action: ADMISSION_ACTION,
                    now: NOW as i64,
                },
                &DevelopmentGate {
                    until,
                    transient: false,
                    fail: false,
                },
                &(),
            )
            .await
            .unwrap();
    }
    pub async fn withdraw(&self) {
        self.engine
            .gates()
            .withdraw(
                &self.passport.pseudonym(&scope()).to_hex(),
                "dev-test",
                "test-only",
            )
            .await
            .unwrap();
    }
    pub async fn ban(&self) {
        let order = clbs::Order {
            community: "example".into(),
            id: "legal-test".into(),
            subject: self.passport.pseudonym(&scope()).to_hex(),
            reference: "synthetic-authority".into(),
            entered_by: "authority".into(),
            kind: clbs::OrderKind::Legal {
                authority: "test-authority".into(),
            },
            scope: clbs::Scope::All,
            period: clbs::Period {
                starts_at: NOW as i64,
                ends_at: Some((NOW + 3600) as i64),
            },
        };
        let proof = SigningKey::from_bytes(&[7; 32])
            .sign(&order.signing_payload().unwrap())
            .to_bytes()
            .to_vec();
        clbs::Gate::new(
            clbs::LibsqlStore::new(&self.db, "example").unwrap(),
            Authority,
            self.clock.clone(),
        )
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    }
}

// The wallet trusts the selected origin's authenticated ring, then verifies the
// server-signed request. No unchecked PresentationRequest enters Passport::present.
pub async fn present<S: Storage>(
    engine: &Engine<S>,
    passport: &Passport,
    rng: &mut StdRng,
    challenge: &Challenge,
    now: u64,
) -> Presentation {
    let ring = engine.snapshot(now).await.unwrap().signing_keys;
    let origin =
        AuthenticatedCommunity::from_authenticated_origin(engine.community().clone(), ring);
    passport
        .present(rng, &origin, challenge.signed_request(), now)
        .unwrap()
}
