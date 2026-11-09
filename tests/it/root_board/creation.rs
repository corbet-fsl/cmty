//! Genuine separate first Root through the same joint passport path.
use super::*;
use crate::support;
type Policy = cplc::Policy<
    cmty::adapters::SharedRulebook<crbk::LibsqlStore>,
    cplc::LibsqlStore,
    csgn::LibsqlStore,
>;

pub(super) async fn holder(
    rng: &mut StdRng,
    global: &IssuerKey,
    common: &IssuerKey,
    policy: &mut Policy,
    descriptor: &RootBoardPublicKey,
    expected: &AuthenticatedCommunity,
    seed: u8,
) -> OpaqueHolder {
    let gate = GateId::new("global-test").unwrap();
    let mut holder =
        OpaqueHolder::from_seed_and_sealing_key(&mut [seed; 32], &mut [seed + 1; 32], b"root-test")
            .unwrap();
    let challenge = IssuanceChallenge::generate(rng);
    let request = holder
        .begin_issuance(rng, global.public_key(), &challenge)
        .unwrap();
    let blind = global
        .issue_blind(
            rng,
            &request,
            &challenge,
            &PassportAttributes::new(EXPIRY, 7).with_gate(gate.clone(), EXPIRY),
        )
        .unwrap();
    holder.finish_issuance(&blind).unwrap();

    let mut source_signer = csgn::Signer::new(
        "source",
        csgn::SecretKey::from_seed(&mut [19; 32]),
        NOW,
        EXPIRY - NOW,
    )
    .unwrap();
    let expected_source = AuthenticatedCommunity::from_authenticated_origin(
        CommunityId::new("source").unwrap(),
        source_signer.key_ring().clone(),
    );
    let context = RootBoardIssuanceContext::new(
        rng,
        PresentationRequest::for_epoch(
            &mut StdRng::seed_from_u64(1702),
            CommunityId::new("source").unwrap(),
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
        .begin_root_board_issuance(rng, expected, &signed, &expected_source, &signed_source, AT)
        .unwrap();
    let verified =
        verify_root_board_issuance(&[global.public_key().clone()], &context, &issuance, AT)
            .unwrap();
    // This fixture supplies a real credential from its issuer; authorization of
    // the source role belongs to the separate issuance-service tests.
    let blind = issue_blind_root_board(rng, common, descriptor, verified, AT).unwrap();
    holder.finish_root_board_issuance(&blind).unwrap();
    holder
}

pub(super) async fn enrol(
    engine: &Engine<cmty::storage::LibsqlStorage>,
    holder: &OpaqueHolder,
    expected: &AuthenticatedCommunity,
    rng: &mut StdRng,
    user: ckyh::Uuid,
    handle: &str,
    device_key: [u8; 32],
) -> cmbr::Login {
    let challenge = engine.begin(rng, AT).await.unwrap();
    let proof = holder
        .present_root_board(rng, expected, challenge.signed_request(), AT)
        .unwrap();
    let verified = engine
        .verify_root_board(&challenge, &proof, AT)
        .await
        .unwrap();
    assert_eq!(
        verified.member_id(),
        holder.pseudonym(engine.community()).to_hex()
    );
    let (request, pending) = engine.begin_registration(verified, user, AT).await.unwrap();
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
        .begin_login(user, credential)
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
        .authorize_device_key(&login.authentication, device_key)
        .await
        .unwrap();
    engine
        .membership()
        .reserve_handle(&login.authentication, handle, &[])
        .await
        .unwrap();
    login
}

pub(super) async fn bootstrap(fixture: &mut Root, holder: &OpaqueHolder) {
    let devices = [ed25519_dalek::SigningKey::from_bytes(&[23; 32])
        .verifying_key()
        .to_bytes()];
    let login = enrol(
        &fixture.engine,
        holder,
        &fixture.expected,
        &mut fixture.rng,
        ckyh::Uuid::from_u128(u128::MAX),
        "separate_root",
        devices[0],
    )
    .await;
    let member = holder.pseudonym(fixture.engine.community()).to_hex();
    let until = fixture.descriptor.expires_at();
    let bytes =
        support::creation_invitation(&fixture.engine, &login.authentication, AT, until).await;
    let session = support::Session::new(&login.authentication, until);
    let challenge = fixture.engine.begin(&mut fixture.rng, AT).await.unwrap();
    let proof = holder
        .present_root_board(
            &mut fixture.rng,
            &fixture.expected,
            challenge.signed_request(),
            AT,
        )
        .unwrap();
    let outcome = fixture
        .engine
        .finish_root_board_with(
            &challenge,
            &proof,
            Admission {
                authentication: &login.authentication,
                session: &session,
                creation: Some(&bytes),
                devices: &devices,
                lease: crgs::YearMonth::new(2027, 9).unwrap(),
            },
            AT,
            async |_, _| Ok(Vec::new()),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Issued(_)));
    let actual = fixture
        .engine
        .membership()
        .member(&login.authentication)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(actual.role, crgs::Role::Root);
    assert_eq!(actual.id.as_bytes(), member.as_bytes());
    assert_eq!(
        fixture.engine.membership().community_phase().await.unwrap(),
        cmbr::CommunityPhase::Active
    );
}
