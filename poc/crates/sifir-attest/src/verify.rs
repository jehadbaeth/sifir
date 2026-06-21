use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::mock::mock_verifying_key_sec1;
use crate::report::{Report, MEASUREMENT_SIZE, REPORT_SIZE};

/// Which trust anchor to use when verifying the report signature.
pub enum AttestationKey {
    /// Verify with the fixed mock P-384 key baked into `mock.rs`.
    /// Used in Phases 1 and 2.
    Mock,
    /// Verify with the AMD VCEK certificate chain.
    /// `vcek_chain` is a slice of DER-encoded certificates: [VCEK, ASK, ARK].
    /// Used in Phases 3 and 4.
    Amd { vcek_chain: Vec<Vec<u8>> },
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("attestation report length is {got}, expected {}", REPORT_SIZE)]
    WrongLength { got: usize },

    #[error("signature verification failed")]
    BadSignature,

    #[error("TLS key binding mismatch: report_data[0..32]={report}, SHA-256(pubkey)={computed}")]
    KeyBindingMismatch { report: String, computed: String },

    #[error("measurement mismatch: expected={expected}, got={actual}")]
    MeasurementMismatch { expected: String, actual: String },

    #[error("AMD certificate chain error: {0}")]
    CertChain(String),

    #[error("internal error: {0}")]
    Internal(String),
}

/// Verify an attestation report.
///
/// # Arguments
/// * `report_bytes` — Raw 1184-byte AMD SEV-SNP attestation report.
/// * `key` — Which trust anchor to use for signature verification.
/// * `expected_measurement` — Expected 48-byte software measurement.
///   Pass `[0u8; 48]` to skip the measurement check (useful during initial setup
///   when the measurement is not yet known).
/// * `tls_pubkey_der` — DER-encoded SubjectPublicKeyInfo of the server's TLS certificate.
///   Verified to match the hash embedded in `report_data`.
pub fn verify(
    report_bytes: &[u8; REPORT_SIZE],
    key: &AttestationKey,
    expected_measurement: &[u8; MEASUREMENT_SIZE],
    tls_pubkey_der: &[u8],
) -> Result<(), VerifyError> {
    let report = Report::new(*report_bytes);

    verify_key_binding(&report, tls_pubkey_der)?;
    verify_signature(&report, key)?;
    verify_measurement(&report, expected_measurement)?;

    Ok(())
}

fn verify_key_binding(report: &Report, tls_pubkey_der: &[u8]) -> Result<(), VerifyError> {
    let computed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(tls_pubkey_der);
        h.finalize().into()
    };

    let in_report = &report.report_data()[..32];

    if in_report != computed.as_ref() {
        return Err(VerifyError::KeyBindingMismatch {
            report: hex::encode(in_report),
            computed: hex::encode(computed),
        });
    }

    Ok(())
}

fn verify_signature(report: &Report, key: &AttestationKey) -> Result<(), VerifyError> {
    // Build a 96-byte fixed-size P-384 signature from the R and S fields.
    let mut sig_bytes = [0u8; 96];
    sig_bytes[..48].copy_from_slice(report.sig_r());
    sig_bytes[48..].copy_from_slice(report.sig_s());

    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| VerifyError::BadSignature)?;

    let verifying_key = match key {
        AttestationKey::Mock => {
            let sec1 = mock_verifying_key_sec1();
            VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| VerifyError::Internal(e.to_string()))?
        }
        AttestationKey::Amd { vcek_chain } => {
            crate::amd_certs::vcek_verifying_key(vcek_chain)?
        }
    };

    verifying_key
        .verify(report.signed_region(), &sig)
        .map_err(|_| VerifyError::BadSignature)
}

fn verify_measurement(
    report: &Report,
    expected: &[u8; MEASUREMENT_SIZE],
) -> Result<(), VerifyError> {
    let zero = [0u8; MEASUREMENT_SIZE];
    if expected == &zero {
        return Ok(());
    }

    if report.measurement() != expected {
        return Err(VerifyError::MeasurementMismatch {
            expected: hex::encode(expected),
            actual: hex::encode(report.measurement()),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{sign_mock_report, tls_pubkey_hash};

    #[test]
    fn valid_mock_report_passes() {
        let pubkey = b"fake-tls-pubkey-der-bytes";
        let measurement = [0xaa_u8; MEASUREMENT_SIZE];
        let hash = tls_pubkey_hash(pubkey);
        let report = sign_mock_report(&hash, &measurement);

        verify(
            report.as_bytes(),
            &AttestationKey::Mock,
            &measurement,
            pubkey,
        )
        .expect("valid mock report should pass verification");
    }

    #[test]
    fn wrong_measurement_rejected() {
        let pubkey = b"fake-tls-pubkey-der-bytes";
        let measurement = [0xaa_u8; MEASUREMENT_SIZE];
        let hash = tls_pubkey_hash(pubkey);
        let report = sign_mock_report(&hash, &measurement);

        let wrong = [0xbb_u8; MEASUREMENT_SIZE];
        let err = verify(report.as_bytes(), &AttestationKey::Mock, &wrong, pubkey).unwrap_err();

        assert!(
            matches!(err, VerifyError::MeasurementMismatch { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn zero_measurement_skips_check() {
        let pubkey = b"fake-tls-pubkey-der-bytes";
        let measurement = [0xaa_u8; MEASUREMENT_SIZE];
        let hash = tls_pubkey_hash(pubkey);
        let report = sign_mock_report(&hash, &measurement);

        verify(
            report.as_bytes(),
            &AttestationKey::Mock,
            &[0u8; MEASUREMENT_SIZE],
            pubkey,
        )
        .expect("zero measurement = skip check");
    }

    #[test]
    fn wrong_tls_key_rejected() {
        let pubkey = b"correct-pubkey";
        let measurement = [0xaa_u8; MEASUREMENT_SIZE];
        let hash = tls_pubkey_hash(pubkey);
        let report = sign_mock_report(&hash, &measurement);

        let err = verify(
            report.as_bytes(),
            &AttestationKey::Mock,
            &measurement,
            b"wrong-pubkey",
        )
        .unwrap_err();

        assert!(
            matches!(err, VerifyError::KeyBindingMismatch { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn tampered_signed_region_rejected() {
        let pubkey = b"fake-tls-pubkey-der-bytes";
        let measurement = [0xaa_u8; MEASUREMENT_SIZE];
        let hash = tls_pubkey_hash(pubkey);
        let mut report = sign_mock_report(&hash, &measurement);

        // Flip a bit in the measurement field (inside the signed region)
        report.as_bytes_mut()[0x090] ^= 0x01;

        let err = verify(
            report.as_bytes(),
            &AttestationKey::Mock,
            &[0u8; MEASUREMENT_SIZE], // skip measurement check so we isolate sig check
            pubkey,
        )
        .unwrap_err();

        assert!(
            matches!(err, VerifyError::BadSignature),
            "tampered signed region should fail sig check; got: {err}"
        );
    }
}
