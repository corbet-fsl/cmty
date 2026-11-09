//! Original authenticated four-artifact activation; no holder or member claim.
use super::*;
use cmty::cgts::cblc::{
    artifacts::{ArtifactBytes, ExtensionArtifacts, NativeVerifierOptions},
    extensions::{EXTENSION_PROOF_BYTES, ExtensionActivation},
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};

pub(super) fn ledger(
    trust: AdmissionTrust,
    store: MemoryStore,
) -> AccountLedger<NativeAccountVerifier> {
    let account = PathBuf::from(std::env::var_os("CBLC_PROOF_DIRECTORY").unwrap());
    assert!(account.is_absolute());
    // The reviewed product input helper preserves capture/init.json unchanged
    // and places both separately authenticated snapshots under this job root.
    let capture = account.parent().unwrap().join("capture");
    let record = account.parent().unwrap().parent().unwrap().join("record");
    let init: Value =
        serde_json::from_slice(&std::fs::read(capture.join("init.json")).unwrap()).unwrap();
    let config: Value =
        serde_json::from_slice(&std::fs::read(record.join("config.json")).unwrap()).unwrap();
    let pin = data_encoding::HEXLOWER
        .decode(config["manifestSha256"].as_str().unwrap().as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = std::fs::read(record.join("manifest.json")).unwrap();
    let circuits = std::fs::read(record.join("circuits.json")).unwrap();
    let keys = std::fs::read(record.join("keys.json")).unwrap();
    let g1 = std::fs::read(record.join("setup/g1.dat")).unwrap();
    let g2 = std::fs::read(record.join("setup/g2.dat")).unwrap();
    let artifacts = ExtensionArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: pin,
        circuit: &circuits,
        keys: &keys,
        srs_g1: &g1,
        srs_g2: &g2,
    })
    .unwrap();
    let options = NativeVerifierOptions {
        executable: std::env::var_os("CBLC_BB").unwrap().into(),
        timeout: Duration::from_secs(180),
        maximum_parallel: 1,
        max_proof_bytes: EXTENSION_PROOF_BYTES,
        threads: 1,
        memory_megabytes: 8192,
    };
    AccountLedger::with_store(
        store,
        trust,
        AccountLedgerPolicy {
            account: serde_json::from_value(init["policy"].clone()).unwrap(),
            max_authorization_seconds: 100,
            max_proof_bytes: EXTENSION_PROOF_BYTES,
            checkpoint_period_seconds: 1000,
        },
        super::super::enrollment::native::verifier(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
    .with_extensions(
        serde_json::from_value(init["extension"].clone()).unwrap(),
        NativeExtensionVerifier::new(options.clone(), options, artifacts).unwrap(),
        ExtensionLimits {
            global_burst: 1000,
            subject_burst: 500,
            replenish: Duration::from_secs(1),
            maximum_keys: NonZeroUsize::new(32).unwrap(),
        },
        ExtensionActivation {
            account: serde_json::from_value(init["activation"]["account"].clone()).unwrap(),
            proof: data_encoding::HEXLOWER
                .decode(init["activation"]["proof"].as_str().unwrap().as_bytes())
                .unwrap(),
        },
    )
    .unwrap()
}
