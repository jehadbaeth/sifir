/// Custom rustls ServerCertVerifier that performs RA-TLS attestation verification
/// instead of the standard CA chain check.
use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use sifir_attest::{verify, AttestationKey, MEASUREMENT_SIZE};
use x509_cert::der::{Decode, Encode};

use sifir_attest::attest_ext::{AttestationExtension, AttestationMode, ATTEST_OID_STR};

#[derive(Debug)]
pub struct AttestationVerifier {
    expected_measurement: [u8; MEASUREMENT_SIZE],
    mode: VerifierMode,
    crypto_provider: Arc<CryptoProvider>,
}

#[derive(Debug, Clone, Copy)]
pub enum VerifierMode {
    Mock,
    AmdSevSnp,
}

impl AttestationVerifier {
    pub fn new(
        expected_measurement: [u8; MEASUREMENT_SIZE],
        mode: VerifierMode,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            expected_measurement,
            mode,
            crypto_provider,
        }
    }
}

impl ServerCertVerifier for AttestationVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Parse the X.509 certificate.
        let cert = x509_cert::Certificate::from_der(end_entity.as_ref())
            .map_err(|e| TlsError::General(format!("cert parse error: {e}")))?;

        // Extract the SubjectPublicKeyInfo DER — this is what we hash for the binding check.
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| TlsError::General(format!("SPKI encode error: {e}")))?;

        // Find and parse the attestation extension.
        let attest_ext = extract_attest_extension(&cert)?;

        // Decode the report bytes.
        let report_raw = attest_ext
            .report_bytes()
            .map_err(|e| TlsError::General(format!("report decode error: {e}")))?;

        // Choose the verification key based on mode and extension mode.
        let attest_key = match (&self.mode, &attest_ext.mode) {
            (VerifierMode::Mock, AttestationMode::Mock) => AttestationKey::Mock,
            (VerifierMode::AmdSevSnp, AttestationMode::AmdSevSnp) => {
                let chain = attest_ext
                    .vcek_chain_der()
                    .map_err(|e| TlsError::General(format!("cert chain decode: {e}")))?;
                AttestationKey::Amd { vcek_chain: chain }
            }
            _ => {
                return Err(TlsError::General(format!(
                    "mode mismatch: client={:?}, server={:?}",
                    self.mode, attest_ext.mode
                )));
            }
        };

        // Run the core attestation verification.
        verify(
            &report_raw,
            &attest_key,
            &self.expected_measurement,
            &spki_der,
        )
        .map_err(|e| TlsError::General(format!("attestation failed: {e}")))?;

        println!("[client] attestation verified successfully");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn extract_attest_extension(
    cert: &x509_cert::Certificate,
) -> Result<AttestationExtension, TlsError> {
    use const_oid::ObjectIdentifier;

    let oid: ObjectIdentifier = ATTEST_OID_STR
        .parse()
        .map_err(|e| TlsError::General(format!("OID parse error: {e}")))?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[]);

    let ext = extensions
        .iter()
        .find(|e| e.extn_id == oid)
        .ok_or_else(|| TlsError::General("no Sifir attestation extension in server cert".into()))?;

    AttestationExtension::from_bytes(ext.extn_value.as_bytes())
        .map_err(|e| TlsError::General(format!("attestation extension parse error: {e}")))
}
