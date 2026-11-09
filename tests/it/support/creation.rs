//! Genuine fixture creation. Role entitlement never substitutes for the
//! original passport, configured gates or atomic first-Root admission.
use super::*;

/// The fixture host's exact genuine login and original session deadline.
pub struct Session {
    authentication: ckyh::Authentication,
    until: u64,
}

impl Session {
    /// Retain this genuine SDK login and the fixture host's original deadline.
    pub fn new(authentication: &ckyh::Authentication, until: u64) -> Self {
        Self {
            authentication: authentication.clone(),
            until,
        }
    }
}

impl cmbr::RoleSession for Session {
    fn valid_until(&self) -> u64 {
        self.until
    }

    fn check(&self, authentication: &ckyh::Authentication, observed: u64) -> cmbr::Result<()> {
        if observed < self.until
            && authentication.community() == self.authentication.community()
            && authentication.member() == self.authentication.member()
            && authentication.credential_id() == self.authentication.credential_id()
        {
            Ok(())
        } else {
            Err(cmbr::Error::Identity)
        }
    }
}

/// Record the creation of the community for the genuinely enrolled creator and
/// return the creation id that its first-admin admission presents.
pub async fn creation_invitation<S: Storage>(
    engine: &Engine<S>,
    authentication: &ckyh::Authentication,
    _now: u64,
    until: u64,
) -> String {
    let row = engine.membership().resume(authentication).await.unwrap();
    assert_eq!(
        engine
            .membership()
            .initialize_community_creation("fixture-first-root", row.subject().as_bytes(), until)
            .await
            .unwrap(),
        cmbr::CommunityPhase::Creating
    );
    "fixture-first-root".to_owned()
}

/// Establish a separate actual Root using an independently issued real
/// passport under the original full fixture Rulebook, before the target member.
pub async fn bootstrap<S: Storage>(
    engine: &Engine<S>,
    passport: &Passport,
    rng: &mut StdRng,
    now: u64,
) {
    let user = ckyh::Uuid::from_u128(u128::MAX);
    let challenge = engine.begin(rng, now).await.unwrap();
    let presentation = present(engine, passport, rng, &challenge, now).await;
    let verified = engine
        .verify(rng, &challenge, &presentation, now)
        .await
        .unwrap();
    let root_subject = passport.pseudonym(engine.community()).to_hex();
    assert_eq!(verified.member_id(), root_subject);
    let (request, pending) = engine
        .begin_registration(verified, user, now)
        .await
        .unwrap();
    let mut token = SoftToken::new(true).unwrap().0;
    let mut options = request.public_key;
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let registered = token
        .perform_register(ckyh::Url::parse(ORIGIN).unwrap(), options, 300_000)
        .unwrap();
    let credential: ckyh::CredentialID = registered.raw_id.clone().into();
    engine
        .membership()
        .finish_registration(pending, registered.into())
        .await
        .unwrap();
    let (request, pending) = engine
        .membership()
        .begin_login(user, credential)
        .await
        .unwrap();
    let assertion = token
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            request.public_key,
            300_000,
        )
        .unwrap();
    let login = engine
        .membership()
        .finish_login(pending, assertion.into())
        .await
        .unwrap();
    let root_devices = [SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes()];
    assert_ne!(root_devices[0], DEVICES[0]);
    engine
        .membership()
        .authorize_device_key(&login.authentication, root_devices[0])
        .await
        .unwrap();
    engine
        .membership()
        .reserve_handle(&login.authentication, "fixture_root", &[])
        .await
        .unwrap();
    let snapshot = engine.snapshot(now).await.unwrap();
    engine
        .gates()
        .run(
            cgts::Context {
                snapshot: &snapshot.rules,
                subject: &root_subject,
                action: ADMISSION_ACTION,
                now: now as i64,
            },
            &DevelopmentGate {
                until: EXPIRY as i64,
                transient: false,
                fail: false,
            },
            &(),
        )
        .await
        .unwrap();
    let invitation = creation_invitation(engine, &login.authentication, now, now + 60).await;
    let session = Session::new(&login.authentication, now + 60);
    let challenge = engine.begin(rng, now).await.unwrap();
    let presentation = present(engine, passport, rng, &challenge, now).await;
    let outcome = engine
        .finish(
            rng,
            &challenge,
            &presentation,
            Admission {
                authentication: &login.authentication,
                devices: &root_devices,
                lease: crgs::YearMonth::new(2027, 9).unwrap(),
                session: &session,
                creation: Some(&invitation),
            },
            now,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Issued(_)));
    assert_eq!(
        engine
            .membership()
            .resume(&login.authentication)
            .await
            .unwrap()
            .state(),
        cmbr::State::Admitted
    );
    assert_eq!(
        engine
            .membership()
            .member(&login.authentication)
            .await
            .unwrap()
            .unwrap()
            .role,
        crgs::Role::Admin
    );
    assert_eq!(
        engine.membership().community_phase().await.unwrap(),
        cmbr::CommunityPhase::Active
    );
}
