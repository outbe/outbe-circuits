//! The three places the proof system is pinned must agree.
//!
//! `bb` derives the key, `barretenberg-rs` verifies with it and the L2
//! manifest names the system those bytes belong to. If they drift, CI happily
//! reproduces keys with a `bb` the runtime verifier does not use. This crate is
//! the one place that can see all three — it is the only member depending on
//! both the L2 registry and the backend — which is why the check lives here.
//!
//! No proving, no toolchain: three `include_str!`s and a TOML parse.

/// The logical name the L2 manifest gives `bb`-derived UltraHonkKeccak keys.
/// Not derivable from a version string, so it is pinned by hand on both sides
/// and asserted equal here and in `xtask l2 verify`.
const PROOF_SYSTEM: &str = "bb-keccak-v1";

#[test]
fn bb_pin_matches_the_barretenberg_rs_pin() {
    let mise: toml::Value = toml::from_str(include_str!("../../../mise.toml")).unwrap();
    let bb = mise["tools"]["bb"]["version"]
        .as_str()
        .expect("mise bb pin");

    // The pin lives in [workspace.dependencies]; the backend inherits it.
    // Assert the inheritance too, or this test would be reading a version the
    // backend does not use.
    let backend: toml::Value =
        toml::from_str(include_str!("../../../crates/outbe-zk-backend/Cargo.toml")).unwrap();
    assert!(
        backend["dependencies"]["barretenberg-rs"]["workspace"]
            .as_bool()
            .unwrap_or(false),
        "outbe-zk-backend must inherit barretenberg-rs from the workspace"
    );
    let workspace: toml::Value = toml::from_str(include_str!("../../../Cargo.toml")).unwrap();
    let crate_pin = workspace["workspace"]["dependencies"]["barretenberg-rs"]["version"]
        .as_str()
        .expect("barretenberg-rs pin");

    assert_eq!(
        bb,
        crate_pin.trim_start_matches('='),
        "the mise bb pin and the barretenberg-rs pin must move together"
    );
}

#[test]
fn both_manifests_name_the_same_proof_system() {
    let l2: toml::Value = toml::from_str(include_str!(
        "../../../crates/outbe-l2-zk-canonical/l2/manifest.toml"
    ))
    .unwrap();
    let l1: toml::Value = toml::from_str(include_str!(
        "../../../crates/outbe-zk-canonical/circuits/manifest.toml"
    ))
    .unwrap();

    assert_eq!(l2["proof_system"].as_str(), Some(PROOF_SYSTEM));
    assert_eq!(
        l1["proof_system"].as_str(),
        Some(PROOF_SYSTEM),
        "the L1 and L2 manifests must pin one proof system"
    );
}
