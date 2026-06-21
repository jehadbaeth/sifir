use std::sync::Arc;

use anyhow::Context;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use sifir_attest::{attest_ext::AttestationExtension, mock::sign_mock_report};
use x509_cert::der::{Decode, Encode};

use crate::attest_ext::ATTEST_OID_ARCS;

#[cfg(feature = "real-attestation")]
use crate::amd_attestation;

#[cfg(feature = "gpu-cc")]
use crate::gpu_attestation;

pub struct TlsSetup {
    pub server_config: Arc<ServerConfig>,
    /// The software measurement embedded in the attestation report.
    /// All-zeros in mock mode; real SHA-384 in Phases 3+.
    pub measurement: [u8; 48],
}

/// Build a TLS ServerConfig with a mock AMD SEV-SNP attestation extension.
///
/// The TLS certificate is self-signed. The attestation extension contains
/// a mock report whose `report_data` field is bound to SHA-256 of the cert's
/// SubjectPublicKeyInfo — the standard RA-TLS binding.
pub async fn build_mock_setup() -> anyhow::Result<TlsSetup> {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate P-256 keypair")?;

    // Two-step: extract SPKI DER from a temp cert so we can hash it before
    // generating the real cert (the attestation report must be signed first).
    let spki_der = extract_spki_der(&key_pair)?;
    let pubkey_hash: [u8; 32] = Sha256::digest(&spki_der).into();

    let measurement = [0u8; 48];
    let report = sign_mock_report(&pubkey_hash, &measurement);

    let config = build_server_cert(key_pair, AttestationExtension::new_mock(report.as_bytes()))?;

    Ok(TlsSetup {
        server_config: Arc::new(config),
        measurement,
    })
}

/// Build a TLS ServerConfig using a real AMD SEV-SNP attestation report.
///
/// Only available when compiled with `--features real-attestation`.
/// Requires running inside an AMD SEV-SNP VM with /dev/snp-guest accessible.
///
/// `product`: AMD product name for KDS lookup ("Milan", "Genoa", etc.).
/// Azure DCasv5 uses "Milan"; Azure NCC H100 v5 uses "Genoa".
#[cfg(feature = "real-attestation")]
pub async fn build_amd_setup(product: &str) -> anyhow::Result<TlsSetup> {
    let (key_pair, _pubkey_hash, user_data) = generate_keypair_and_hash()?;

    println!("[sifir-server] fetching AMD SNP attestation report...");
    let (report_bytes, vcek_chain) = amd_attestation::get_report_and_chain(user_data, product)
        .await
        .context("get AMD SNP report + VCEK chain")?;

    let measurement = extract_measurement(&report_bytes);
    let config = build_server_cert(
        key_pair,
        AttestationExtension::new_amd(&report_bytes, &vcek_chain),
    )?;

    Ok(TlsSetup {
        server_config: Arc::new(config),
        measurement,
    })
}

/// Build a TLS ServerConfig with AMD SEV-SNP + NVIDIA GPU CC attestation.
///
/// Requires `--features real-attestation,gpu-cc` and running on Azure NCC H100 v5
/// with the NVIDIA attestation SDK installed.
///
/// `script_path`: path to `poc/inference/gpu_attest.py`.
#[cfg(all(feature = "real-attestation", feature = "gpu-cc"))]
pub async fn build_amd_gpu_setup(product: &str, script_path: &str) -> anyhow::Result<TlsSetup> {
    let (key_pair, pubkey_hash, user_data) = generate_keypair_and_hash()?;

    println!("[sifir-server] fetching AMD SNP attestation report...");
    let (report_bytes, vcek_chain) = amd_attestation::get_report_and_chain(user_data, product)
        .await
        .context("get AMD SNP report + VCEK chain")?;

    let measurement = extract_measurement(&report_bytes);

    println!("[sifir-server] fetching GPU CC attestation JWT...");
    let gpu_jwt = gpu_attestation::get_gpu_jwt(&pubkey_hash, script_path)
        .await
        .context("get GPU attestation JWT")?;

    let ext = AttestationExtension::new_amd(&report_bytes, &vcek_chain).with_gpu_jwt(gpu_jwt);
    let config = build_server_cert(key_pair, ext)?;

    Ok(TlsSetup {
        server_config: Arc::new(config),
        measurement,
    })
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn extract_spki_der(key_pair: &KeyPair) -> anyhow::Result<Vec<u8>> {
    let params = CertificateParams::default();
    let temp_cert = params.self_signed(key_pair).context("generate temp cert")?;
    let x509 = x509_cert::Certificate::from_der(temp_cert.der()).context("parse temp cert DER")?;
    x509.tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encode SPKI DER")
}

/// Returns (key_pair, pubkey_hash[32], user_data[64]).
/// pubkey_hash = SHA-256(SPKI DER); user_data has it in bytes [0..32].
#[cfg(feature = "real-attestation")]
fn generate_keypair_and_hash() -> anyhow::Result<(KeyPair, [u8; 32], [u8; 64])> {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate P-256 keypair")?;
    let spki_der = extract_spki_der(&key_pair)?;
    let pubkey_hash: [u8; 32] = Sha256::digest(&spki_der).into();
    let mut user_data = [0u8; 64];
    user_data[..32].copy_from_slice(&pubkey_hash);
    Ok((key_pair, pubkey_hash, user_data))
}

#[cfg(feature = "real-attestation")]
fn extract_measurement(report_bytes: &[u8]) -> [u8; 48] {
    report_bytes[0x090..0x090 + 48]
        .try_into()
        .expect("report is at least 0xC0 bytes")
}

fn build_server_cert(key_pair: KeyPair, ext: AttestationExtension) -> anyhow::Result<ServerConfig> {
    let ext_bytes = ext.to_bytes();
    let mut params = CertificateParams::default();
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            ATTEST_OID_ARCS,
            ext_bytes,
        ));
    let cert = params
        .self_signed(&key_pair)
        .context("generate attested cert")?;

    let rustls_cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()),
    );

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], priv_key)
        .context("build ServerConfig")
}
