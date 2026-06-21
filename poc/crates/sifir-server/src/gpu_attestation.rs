/// NVIDIA GPU CC attestation — Phase 4 (Azure NCC H100 v5).
///
/// Only compiled when `--features gpu-cc` is set. Calls the Python sidecar
/// `poc/inference/gpu_attest.py` via subprocess (NVIDIA's attestation SDK
/// is Python-only; subprocess avoids brittle FFI).
///
/// # Prerequisites
/// - Running on Azure NCC H100 v5 (Standard_NCC40ads_H100_v5)
/// - GPU CC mode active: `nvidia-smi --query-gpu=cc_mode --format=csv,noheader`
/// - NVIDIA attestation SDK installed: `pip install nv-attestation-sdk>=1.4.0`
/// - `gpu_attest.py` path passed at runtime via --gpu-attest-script CLI arg

use anyhow::{bail, Context};

/// Fetch a NVIDIA GPU CC attestation JWT.
///
/// `tls_pubkey_hash`: SHA-256 of the TLS SPKI DER — used as the nonce to
/// bind the GPU attestation to this specific TLS session.
///
/// `script_path`: absolute path to `poc/inference/gpu_attest.py`.
///
/// Returns the NRAS JWT string for embedding in the TLS cert extension.
pub async fn get_gpu_jwt(
    tls_pubkey_hash: &[u8; 32],
    script_path: &str,
) -> anyhow::Result<String> {
    let nonce = hex::encode(tls_pubkey_hash);

    let output = tokio::process::Command::new("python3")
        .args([script_path, "--nonce", &nonce])
        .output()
        .await
        .with_context(|| format!("spawn gpu_attest.py (script_path={script_path})"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gpu_attest.py exited with {}: {stderr}", output.status);
    }

    #[derive(serde::Deserialize)]
    struct GpuAttestResult {
        jwt: String,
    }

    let result: GpuAttestResult = serde_json::from_slice(&output.stdout)
        .context("parse gpu_attest.py JSON output")?;

    Ok(result.jwt)
}
