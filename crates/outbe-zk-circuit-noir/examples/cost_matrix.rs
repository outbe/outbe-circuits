//! One-cell PK-build cost measurement, parameterized via CLI args.
//!
//! Prints exactly one JSON line on stdout (so a harness can drive it
//! cell-by-cell as separate processes and aggregate). All non-JSON
//! output (barretenberg internal logs) goes to stderr by default.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI example binary that emits a JSON line on stdout by design"
)]
//!
//! Usage:
//!   cost_matrix --circuit <path> \
//!               --oracle <keccak|poseidon2> \
//!               --zk <on|off> \
//!               --low-mem <on|off> \
//!               --ipa <on|off> \
//!               [--label <name>]

use std::time::Instant;

use barretenberg_rs::{
    backends::FfiBackend,
    generated_types::{CircuitInputNoVK, ProofSystemSettings},
    BarretenbergApi,
};

fn arg(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn peak_rss_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return -1.0;
    }
    let max_rss = ru.ru_maxrss as f64;
    #[cfg(target_os = "macos")]
    let mib = max_rss / (1024.0 * 1024.0);
    #[cfg(not(target_os = "macos"))]
    let mib = max_rss / 1024.0;
    mib
}

fn fetch_grumpkin_g1() -> anyhow::Result<Vec<u8>> {
    let path = "/tmp/grumpkin_g1.dat";
    if let Ok(b) = std::fs::read(path) {
        return Ok(b);
    }
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?
        .get("https://crs.aztec.network/grumpkin_g1.dat")
        .send()?;
    let bytes = resp.bytes()?.to_vec();
    std::fs::write(path, &bytes)?;
    Ok(bytes)
}

fn read_bytecode_b64(path: &str) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&raw)?;
    let bc = json
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'bytecode' field"))?
        .trim()
        .to_string();
    Ok(bc)
}

fn run_cell(
    circuit_path: &str,
    oracle: &str,
    zk_on: bool,
    low_mem: bool,
    ipa: bool,
) -> anyhow::Result<(u128, f64)> {
    // Belt-and-suspenders: writes both env vars + C++ globals.
    outbe_zk_circuit_noir::barretenberg::api::configure_memory(low_mem, None);

    let bc_b64 = read_bytecode_b64(circuit_path)?;
    let acir = outbe_zk_circuit_noir::circuit::get_acir_buffer_uncompressed(&bc_b64)
        .map_err(|e| anyhow::anyhow!("get_acir_buffer_uncompressed: {e}"))?;

    // For the regular path, auto-size the BN254 SRS to the circuit's
    // subgroup so small-circuit measurements aren't inflated by an
    // oversized SRS.
    //
    // For ipa=true (rolluphonk), barretenberg's internal allocations
    // need significantly more BN254 points than the circuit's nominal
    // subgroup. Fall back to a fixed 2^22 here so all rolluphonk cells
    // succeed; this adds ~256 MB to peak RSS uniformly across cells.
    if ipa {
        let backend = FfiBackend::new().map_err(|e| anyhow::anyhow!("FfiBackend: {e}"))?;
        let mut api = BarretenbergApi::new(backend);
        let num_bn = 1u32 << 22;
        let want = num_bn as usize * 64;
        let g1_path = "/tmp/bn254_g1.dat";
        let mut g1: Vec<u8> = std::fs::read(g1_path).unwrap_or_default();
        if g1.len() < want {
            let g1_end: u64 = num_bn as u64 * 64 - 1;
            let resp = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()?
                .get("https://crs.aztec.network/g1.dat")
                .header("Range", format!("bytes=0-{g1_end}"))
                .send()?;
            g1 = resp.bytes()?.to_vec();
            std::fs::write(g1_path, &g1)?;
        }
        let g1 = g1[..want].to_vec();
        const BN254_G2: [u8; 128] = [
            1, 24, 196, 213, 184, 55, 188, 194, 188, 137, 181, 179, 152, 181, 151, 78, 159, 89, 68,
            7, 59, 50, 7, 139, 126, 35, 31, 236, 147, 136, 131, 176, 38, 14, 1, 178, 81, 246, 241,
            199, 231, 255, 78, 88, 7, 145, 222, 232, 234, 81, 216, 122, 53, 142, 3, 139, 78, 254,
            48, 250, 192, 147, 131, 193, 34, 254, 189, 163, 192, 192, 99, 42, 86, 71, 91, 66, 20,
            229, 97, 94, 17, 230, 221, 63, 150, 230, 206, 162, 133, 74, 135, 212, 218, 204, 94, 85,
            4, 252, 99, 105, 247, 17, 15, 227, 210, 81, 86, 193, 187, 154, 114, 133, 156, 242, 160,
            70, 65, 249, 155, 164, 238, 65, 60, 128, 218, 106, 95, 228,
        ];
        api.srs_init_srs(&g1, num_bn, &BN254_G2)
            .map_err(|e| anyhow::anyhow!("srs_init_srs (ipa path): {e}"))?;
    } else {
        let _ =
            outbe_zk_circuit_noir::barretenberg::srs::setup_srs_from_bytecode(&bc_b64, None, false)
                .map_err(|e| anyhow::anyhow!("setup_srs_from_bytecode: {e}"))?;
    }

    let backend = FfiBackend::new().map_err(|e| anyhow::anyhow!("FfiBackend: {e}"))?;
    let mut api = BarretenbergApi::new(backend);

    if ipa {
        let grumpkin = fetch_grumpkin_g1()?;
        let num_grumpkin = (grumpkin.len() / 64) as u32;
        api.srs_init_grumpkin_srs(&grumpkin, num_grumpkin)
            .map_err(|e| anyhow::anyhow!("srs_init_grumpkin_srs: {e}"))?;
    }

    let settings = ProofSystemSettings {
        ipa_accumulation: ipa,
        oracle_hash_type: oracle.to_string(),
        disable_zk: !zk_on,
        optimized_solidity_verifier: false,
    };

    let circuit = CircuitInputNoVK {
        name: "matrix-cell".to_string(),
        bytecode: acir,
    };

    let t0 = Instant::now();
    api.circuit_compute_vk(circuit, settings)
        .map_err(|e| anyhow::anyhow!("circuit_compute_vk: {e}"))?;
    let elapsed = t0.elapsed();
    Ok((elapsed.as_millis(), peak_rss_mib()))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let circuit_path = arg(&args, "--circuit").unwrap_or_default();
    let oracle = arg(&args, "--oracle").unwrap_or_else(|| "keccak".to_string());
    let zk_on = arg(&args, "--zk").unwrap_or_else(|| "off".to_string()) == "on";
    let low_mem = arg(&args, "--low-mem").unwrap_or_else(|| "off".to_string()) == "on";
    let ipa = arg(&args, "--ipa").unwrap_or_else(|| "off".to_string()) == "on";
    let label = arg(&args, "--label").unwrap_or_default();

    match run_cell(&circuit_path, &oracle, zk_on, low_mem, ipa) {
        Ok((ms, rss)) => println!(
            r#"{{"label":"{}","circuit":"{}","oracle":"{}","zk":{},"low_mem":{},"ipa":{},"time_ms":{},"peak_rss_mib":{:.2},"ok":true}}"#,
            label, circuit_path, oracle, zk_on, low_mem, ipa, ms, rss
        ),
        Err(e) => {
            let msg = e.to_string().replace('"', "'").replace('\n', " ");
            // Truncate to keep JSON tidy.
            let msg = if msg.len() > 200 { &msg[..200] } else { &msg };
            println!(
                r#"{{"label":"{}","circuit":"{}","oracle":"{}","zk":{},"low_mem":{},"ipa":{},"ok":false,"error":"{}","peak_rss_mib":{:.2}}}"#,
                label,
                circuit_path,
                oracle,
                zk_on,
                low_mem,
                ipa,
                msg,
                peak_rss_mib()
            );
        }
    }
}
