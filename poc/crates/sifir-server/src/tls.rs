use std::sync::Arc;

use anyhow::Context;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use sifir_attest::mock::sign_mock_report;
use x509_cert::der::{Decode, Encode};

use crate::attest_ext::{AttestationExtension, ATTEST_OID_ARCS};

pub struct TlsSetup {
    pub server_config: Arc<ServerConfig>,
    pub cert_der: Vec<u8>,
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
    // 1. Generate a P-256 keypair for TLS.
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("generate P-256 keypair")?;

    // 2. Generate a temporary cert to extract the SubjectPublicKeyInfo DER.
    //    The mock attestation report must be signed BEFORE the real cert is
    //    generated (the report is embedded in the cert's extension), so we
    //    need the SPKI hash first.
    let spki_der: Vec<u8> = {
        let params = CertificateParams::default();
        let temp_cert = params.self_signed(&key_pair).context("generate temp cert")?;
        let x509 = x509_cert::Certificate::from_der(temp_cert.der())
            .context("parse temp cert DER")?;
        x509.tbs_certificate
            .subject_public_key_info
            .to_der()
            .context("encode SPKI")?
    };

    let pubkey_hash: [u8; 32] = Sha256::digest(&spki_der).into();

    // 3. Sign the mock attestation report with the pubkey hash.
    let measurement = [0u8; 48];
    let report = sign_mock_report(&pubkey_hash, &measurement);

    // 4. Encode the extension payload.
    let ext_bytes = AttestationExtension::new_mock(report.as_bytes()).to_bytes();

    // 5. Generate the real cert with the attestation extension.
    let mut params = CertificateParams::default();
    params.custom_extensions.push(
        CustomExtension::from_oid_content(ATTEST_OID_ARCS, ext_bytes),
    );
    let cert = params.self_signed(&key_pair).context("generate attested cert")?;
    let cert_der: Vec<u8> = cert.der().to_vec();

    // 6. Build the rustls ServerConfig.
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()),
    );

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], priv_key)
        .context("build ServerConfig")?;

    Ok(TlsSetup {
        server_config: Arc::new(config),
        cert_der,
        measurement,
    })
}
