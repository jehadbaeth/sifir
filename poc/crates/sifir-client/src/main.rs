mod gpu_verify;
mod request;
mod verifier;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use rustls::crypto::ring::default_provider;
use sifir_attest::MEASUREMENT_SIZE;

use crate::verifier::{AttestationVerifier, VerifierMode};

#[derive(Parser, Debug)]
#[command(about = "Sifir RA-TLS client — verifies attestation before sending any data")]
struct Args {
    /// Server address as host:port (e.g. 127.0.0.1:7443 or sifir.example.com:7443).
    #[arg(long)]
    server: String,

    /// Expected software measurement (48-byte hex string).
    /// Use 96 zeros to skip the measurement check (useful during initial setup).
    #[arg(
        long,
        default_value = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    expected_measurement: String,

    /// Use AMD cert chain verification instead of the mock key.
    /// Default: mock mode (Phases 1 and 2). Pass --amd for Phase 3+.
    #[arg(long, default_value_t = false)]
    amd: bool,

    /// Require and verify NVIDIA GPU CC attestation JWT in the server cert.
    /// Only valid with --amd (Phase 4, Azure NCC H100 v5).
    #[arg(long, default_value_t = false)]
    gpu_cc: bool,

    /// Maximum tokens to generate.
    #[arg(long, default_value_t = 512)]
    max_tokens: u32,

    /// Prompt to send to the inference server.
    prompt: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Parse expected measurement.
    let measurement_hex = args.expected_measurement.trim();
    let measurement_bytes = hex::decode(measurement_hex)
        .context("expected_measurement must be a valid hex string")?;
    if measurement_bytes.len() != MEASUREMENT_SIZE {
        anyhow::bail!(
            "expected_measurement must be {} bytes ({} hex chars), got {} bytes",
            MEASUREMENT_SIZE,
            MEASUREMENT_SIZE * 2,
            measurement_bytes.len()
        );
    }
    let mut expected_measurement = [0u8; MEASUREMENT_SIZE];
    expected_measurement.copy_from_slice(&measurement_bytes);

    let mode = if args.amd {
        VerifierMode::AmdSevSnp
    } else {
        VerifierMode::Mock
    };

    if expected_measurement == [0u8; MEASUREMENT_SIZE] {
        eprintln!("[client] WARNING: measurement check disabled (expected = all-zeros)");
    } else {
        eprintln!(
            "[client] will verify measurement: {}",
            hex::encode(expected_measurement)
        );
    }

    // Set up rustls with our custom attestation verifier.
    let crypto_provider = Arc::new(default_provider());
    let verifier = AttestationVerifier::new(
        expected_measurement,
        mode,
        args.gpu_cc,
        Arc::clone(&crypto_provider),
    );

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    // Build reqwest client using the custom TLS config.
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .context("build HTTP client")?;

    // Construct the server URL.
    let base_url = format!("https://{}", args.server);
    eprintln!("[client] connecting to {base_url}");

    // Send the inference request.
    let resp = request::generate(&client, &base_url, &args.prompt, args.max_tokens)
        .await
        .context("inference request failed")?;

    println!("{}", resp.text);
    eprintln!("[client] tokens used: {}", resp.tokens_used);

    Ok(())
}
