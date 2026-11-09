//! Actual passport, passkey, admitted membership and original role register.
use super::*;
use crate::support;
use crate::support::SoftwareToken;
use cuts::{Cut, CutChallenges, CutStorage};

pub type Issuer = RootBoardIssuer<
    CutChallenges,
    cmty::adapters::SharedRulebook<crbk::LibsqlStore>,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;

pub struct World {
    pub source: Engine<cmty::storage::LibsqlStorage>,
    pub root: Engine<CutStorage>,
    pub issuer: Issuer,
    pub holder: OpaqueHolder,
    pub global: IssuerKey,
    pub source_expected: AuthenticatedCommunity,
    pub root_expected: AuthenticatedCommunity,
    pub descriptor: RootBoardPublicKey,
    pub login: cmbr::Login,
    pub clock: Clock,
    pub cut: Arc<Cut>,
    pub rng: StdRng,
    pub source_db: crlt::Db,
    _directory: tempfile::TempDir,
}

pub async fn passport(rng: &mut StdRng, issuer: &IssuerKey, seed: u8) -> OpaqueHolder {
    let mut holder = OpaqueHolder::from_seed_and_sealing_key(
        &mut [seed; 32],
        &mut [seed.wrapping_add(1); 32],
        b"root-issuance-test",
    )
    .unwrap();
    let store = MemoryStore::new(CommunityId::new("issuer").unwrap(), 10).unwrap();
    let auth = AuthenticatedIssuance::new([seed; 32], [seed.wrapping_add(1); 32]);
    let challenge = issuance_challenge(rng, &store, issuer.public_key(), &auth, NOW + 60)
        .await
        .unwrap();
    let request = holder
        .begin_issuance(rng, issuer.public_key(), &challenge)
        .unwrap();
    let blind = issue_blind_once(
        rng,
        &store,
        issuer,
        &auth,
        &request,
        &challenge,
        &PassportAttributes::new(EXPIRY, 7).with_gate(GateId::new("global-test").unwrap(), EXPIRY),
        NOW,
    )
    .await
    .unwrap();
    holder.finish_issuance(&blind).unwrap();
    holder
}

pub async fn world() -> World {
    let directory = tempfile::tempdir().unwrap();
    let source_db = support::open(
        &format!("file://{}", directory.path().join("source.db").display()),
        "",
    )
    .await;
    let root_db = support::open(
        &format!("file://{}", directory.path().join("root.db").display()),
        "",
    )
    .await;
    let clock = Clock(Arc::new(AtomicI64::new(NOW as i64)));
    let mut rng = StdRng::seed_from_u64(2201);
    let global = IssuerKey::generate(
        &mut rng,
        KeyId::new("global").unwrap(),
        vec![GateId::new("global-test").unwrap()],
    )
    .unwrap();
    let holder = passport(&mut rng, &global, 43).await;
    let (source_policy, _) = support::policies(&source_db, support::rulebook()).await;
    let source_expected = AuthenticatedCommunity::from_authenticated_origin(
        support::scope(),
        source_policy.key_ring().unwrap().clone(),
    );
    let source = Community::new(
        cmty::storage::LibsqlStorage::new(&source_db, support::scope(), 32).unwrap(),
        vec![global.public_key().clone()],
        Parts {
            membership: support::members(&source_db, clock.clone()),
            gates: support::gates(&source_db),
            policy: source_policy,
        },
        support::config(EXPIRY, EXPIRY),
    )
    .unwrap();
    // A separate real passport under this SAME configured global issuer
    // establishes the original first Root. The target holder remains distinct
    // and follows ordinary admission before its explicit existing Admin role.
    let root_secret = HolderSecret::generate(&mut rng);
    let root_passport = support::blind_passport(
        &mut rng,
        &global,
        &root_secret,
        GateId::new("global-test").unwrap(),
        EXPIRY,
        7,
    )
    .await;
    assert_ne!(
        root_passport.pseudonym(source.community()).to_hex(),
        holder.pseudonym(source.community()).to_hex(),
    );
    support::bootstrap(&source, &root_passport, &mut rng, NOW).await;
    let login = enrol(&source, &holder, &source_expected, &mut rng).await;
    let snapshot = source.snapshot(NOW).await.unwrap();
    let subject = holder.pseudonym(source.community()).to_hex();
    source
        .gates()
        .run(
            cgts::Context {
                snapshot: &snapshot.rules,
                subject: &subject,
                action: ADMISSION_ACTION,
                now: NOW as i64,
            },
            &support::DevelopmentGate {
                until: EXPIRY as i64,
                transient: false,
                fail: false,
            },
            &(),
        )
        .await
        .unwrap();
    let challenge = source.begin(&mut rng, NOW).await.unwrap();
    let proof = holder
        .present(&mut rng, &source_expected, challenge.signed_request(), NOW)
        .unwrap();
    let session = support::Session::new(&login.authentication, EXPIRY);
    let outcome = source
        .finish(
            &mut rng,
            &challenge,
            &proof,
            Admission {
                authentication: &login.authentication,
                session: &session,
                creation: None,
                devices: &DEVICES,
                lease: crgs::YearMonth::new(2027, 9).unwrap(),
            },
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Issued(_)));
    let row = source
        .membership()
        .resume(&login.authentication)
        .await
        .unwrap();
    assert_eq!(row.state(), cmbr::State::Admitted);
    assert_eq!(
        source
            .membership()
            .member(&login.authentication)
            .await
            .unwrap()
            .unwrap()
            .role,
        crgs::Role::Member,
    );
    // Provision an existing authoritative role only AFTER actual admission,
    // through the original register owner. This is not voucher bootstrap or a
    // fabricated admitted row; subsequent demotion uses Membership's actor API.
    crgs::Register::new(
        crgs::LibsqlStorage::new(source_db.community("example").unwrap()),
        crgs::ReleasePeriod::default(),
    )
    .set_role(&row.member_id(), crgs::Role::Admin)
    .await
    .unwrap();

    let common = IssuerKey::generate(
        &mut rng,
        KeyId::new("common-root").unwrap(),
        vec![GateId::new("root-board").unwrap()],
    )
    .unwrap();
    let (mut policy, _) = support::policies_in(&root_db, support::rulebook(), "adminboard").await;
    let descriptor = RootBoardPublicKey::from_authenticated_beacon(
        common.public_key().clone(),
        CommunityId::new("adminboard").unwrap(),
        policy.epoch(NOW).await.unwrap(),
        NOW / ROOT_BOARD_COHORT_SECONDS * ROOT_BOARD_COHORT_SECONDS,
    )
    .unwrap();
    policy.publish_root_board(&descriptor, NOW).await.unwrap();
    let root_expected = AuthenticatedCommunity::from_authenticated_origin(
        CommunityId::new("adminboard").unwrap(),
        policy.key_ring().unwrap().clone(),
    );
    let cut = Arc::new(Cut::default());
    let root = Community::new_root_board(
        CutStorage {
            inner: cmty::storage::LibsqlStorage::new(
                &root_db,
                CommunityId::new("adminboard").unwrap(),
                32,
            )
            .unwrap(),
            cut: cut.clone(),
        },
        vec![global.public_key().clone()],
        Parts {
            membership: support::members_in(&root_db, clock.clone(), "adminboard"),
            gates: support::gates_in(&root_db, "adminboard"),
            policy,
        },
        support::config(EXPIRY, EXPIRY),
    )
    .unwrap();
    let issuer = root.root_board_issuer(common, NOW).await.unwrap();
    World {
        source,
        root,
        issuer,
        holder,
        global,
        source_expected,
        root_expected,
        descriptor,
        login,
        clock,
        cut,
        rng,
        source_db,
        _directory: directory,
    }
}

async fn enrol(
    engine: &Engine<cmty::storage::LibsqlStorage>,
    holder: &OpaqueHolder,
    expected: &AuthenticatedCommunity,
    rng: &mut StdRng,
) -> cmbr::Login {
    let challenge = engine.begin(rng, NOW).await.unwrap();
    let proof = holder
        .present(rng, expected, challenge.signed_request(), NOW)
        .unwrap();
    let verified = engine.verify(rng, &challenge, &proof, NOW).await.unwrap();
    assert_eq!(
        verified.member_id(),
        holder.pseudonym(engine.community()).to_hex()
    );
    let (request, pending) = engine
        .begin_registration(verified, USER, NOW)
        .await
        .unwrap();
    let mut device = SoftwareToken::new(true).unwrap().0;
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
    engine
        .membership()
        .finish_registration(pending, response.into())
        .await
        .unwrap();
    let (request, pending) = engine
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
    let login = engine
        .membership()
        .finish_login(pending, response.into())
        .await
        .unwrap();
    engine
        .membership()
        .authorize_device_key(&login.authentication, DEVICES[0])
        .await
        .unwrap();
    engine
        .membership()
        .reserve_handle(&login.authentication, "source_admin", &[])
        .await
        .unwrap();
    login
}

impl World {
    pub async fn begin(&mut self, until: u64) -> RootBoardChallenge {
        let clock = self.clock.clone();
        let cut = self.cut.clone();
        self.source
            .begin_root_board_issuance(
                &self.issuer,
                &mut self.rng,
                &RootBoardSession {
                    authentication: &self.login.authentication,
                    valid_until: until,
                    clock: move || cuts::now(&clock, &cut),
                },
            )
            .await
            .unwrap()
    }

    pub fn request(&mut self, challenge: &RootBoardChallenge) -> RootBoardIssuanceRequest {
        self.holder
            .begin_root_board_issuance(
                &mut self.rng,
                &self.root_expected,
                challenge.signed_context(),
                &self.source_expected,
                challenge.signed_source_request(),
                self.clock.0.load(Ordering::SeqCst) as u64,
            )
            .unwrap()
    }

    pub async fn finish(
        &mut self,
        challenge: &RootBoardChallenge,
        request: &RootBoardIssuanceRequest,
    ) -> cmty::Result<BlindRootBoardCredential> {
        let clock = self.clock.clone();
        let cut = self.cut.clone();
        self.source
            .finish_root_board_issuance(
                &self.issuer,
                &mut self.rng,
                &RootBoardSession {
                    authentication: &self.login.authentication,
                    valid_until: NOW + 120,
                    clock: move || cuts::now(&clock, &cut),
                },
                challenge,
                request,
            )
            .await
    }

    pub async fn context(&self, challenge: &RootBoardChallenge) -> RootBoardIssuanceContext {
        let snapshot = self.root.snapshot(NOW).await.unwrap();
        let signed = snapshot
            .signing_keys
            .verify(challenge.signed_context(), csgn::Kind::Credential, NOW)
            .unwrap();
        RootBoardIssuanceContext::from_bytes(signed.payload()).unwrap()
    }
}
