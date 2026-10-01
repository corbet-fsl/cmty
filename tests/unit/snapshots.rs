use super::*;
use crbk::Storage;

async fn snapshot(seed: u8) -> PolicySnapshot {
    let now = 1_800_000_000;
    let rules = crbk::MemoryStore::default()
        .append(
            "example",
            None,
            crbk::Change {
                rulebook: crbk::Rulebook::default(),
                announced_at: now,
                effective_at: now,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap()
        .snapshot("example", now)
        .unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "example",
        csgn::SecretKey::from_seed(&mut [seed; 32]),
        now as u64,
        86_400,
    )
    .await
    .unwrap();
    PolicySnapshot {
        rules,
        schema_version: 1,
        passport: PassportPolicy {
            epoch: 1,
            valid_until: 1_800_144_000,
            gates: [GateId::new("phone").unwrap()].into(),
        },
        valid_until: now as u64 + 86_400,
        signing_keys: signer.key_ring().unwrap().clone(),
    }
}

#[tokio::test]
async fn every_bound_snapshot_component_invalidates_an_old_challenge_comparison() {
    let original = snapshot(7).await;
    let changed_ring = snapshot(8).await.signing_keys;
    assert!(original.unchanged(&original.clone()));
    for case in 0..8 {
        let mut changed = original.clone();
        match case {
            0 => changed.rules.community = "foreign".into(),
            1 => changed.rules.revision += 1,
            2 => changed.rules.policy_epoch += 1,
            3 => {
                changed.rules.content.insert(
                    crbk::gate_key(crbk::GateLevel::Global, "phone"),
                    serde_json::Value::Bool(true),
                );
            }
            4 => changed.schema_version += 1,
            5 => changed.passport.epoch += 1,
            6 => changed.valid_until += 1,
            7 => changed.signing_keys = changed_ring.clone(),
            _ => unreachable!(),
        }
        assert!(!original.unchanged(&changed), "component {case}");
    }
}

#[test]
fn passport_storage_errors_remain_coarse_and_distinct_from_invalid_proofs() {
    assert_eq!(
        crate::Error::from(cpsd::Error::Storage),
        crate::Error::Storage
    );
    assert_eq!(
        crate::Error::from(cpsd::Error::StorageCapacity),
        crate::Error::Storage
    );
    assert_eq!(
        crate::Error::from(cpsd::Error::InvalidIdentifier("test")),
        crate::Error::Passport
    );
}
