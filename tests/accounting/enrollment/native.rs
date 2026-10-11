//! Required original native artifact owner; no proof substitute is configured.
use super::*;
use cmty::cgts::cblc::artifacts::{AccountArtifacts, ArtifactBytes, NativeVerifierOptions};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    directory: PathBuf,
    manifest_sha256: String,
}
pub(crate) fn verifier() -> NativeAccountVerifier {
    let root = PathBuf::from(
        std::env::var_os("CBLC_PROOF_DIRECTORY")
            .expect("enrollment owner tests require original authenticated native artifacts"),
    );
    assert!(root.is_absolute());
    let config: Config =
        serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
    assert!(config.directory.is_absolute());
    let pin = data_encoding::HEXLOWER
        .decode(config.manifest_sha256.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = std::fs::read(config.directory.join("manifest.json")).unwrap();
    let circuit = std::fs::read(config.directory.join("circuit.json")).unwrap();
    let keys = std::fs::read(config.directory.join("vk.bin")).unwrap();
    let g1 = std::fs::read(config.directory.join("setup/g1.dat")).unwrap();
    let g2 = std::fs::read(config.directory.join("setup/g2.dat")).unwrap();
    let artifacts = AccountArtifacts::authenticate(ArtifactBytes {
        manifest: &manifest,
        manifest_sha256: pin,
        circuit: &circuit,
        keys: &keys,
        srs_g1: &g1,
        srs_g2: &g2,
    })
    .unwrap();
    NativeAccountVerifier::new(
        NativeVerifierOptions {
            executable: std::env::var_os("CBLC_BB")
                .expect("enrollment tests require the maintained native worker")
                .into(),
            timeout: Duration::from_secs(180),
            maximum_parallel: 1,
            max_proof_bytes: 4 * 1024 * 1024,
            threads: 1,
            memory_megabytes: 8192,
        },
        artifacts,
    )
    .unwrap()
}
