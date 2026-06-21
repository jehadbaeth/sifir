/// Mock attestation signer using a fixed P-384 test keypair.
///
/// This is intentionally a weak, known key — its private scalar is
/// committed to this file. It only exists so Phase 1 (local development)
/// can exercise the full RA-TLS verification path without real AMD hardware.
/// Real AMD attestation (Phase 3) replaces this with the VCEK cert chain.
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::report::{Report, MEASUREMENT_SIZE, SIGNED_REGION_SIZE};

// Fixed 48-byte P-384 private key scalar.
// Value: 0x0102...2f30 — clearly non-random, do not use outside tests.
const MOCK_PRIVATE_KEY_SCALAR: [u8; 48] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];

fn mock_signing_key() -> SigningKey {
    SigningKey::from_slice(&MOCK_PRIVATE_KEY_SCALAR)
        .expect("mock private key scalar is a valid P-384 scalar")
}

/// Returns the mock verifying key in uncompressed SEC1 format (97 bytes: 0x04 || x || y).
/// The client stores this and uses it to verify mock attestation reports.
pub fn mock_verifying_key_sec1() -> Vec<u8> {
    let key = mock_signing_key();
    key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

/// Build and sign a mock AMD SEV-SNP attestation report.
///
/// # Arguments
/// * `tls_pubkey_hash` — SHA-256 of the server's TLS public key DER (32 bytes).
///   Written into report_data[0..32]. The client checks this binding.
/// * `measurement` — 48-byte software measurement. Use all-zeros in dev mode
///   to disable measurement checking on the client side.
pub fn sign_mock_report(
    tls_pubkey_hash: &[u8; 32],
    measurement: &[u8; MEASUREMENT_SIZE],
) -> Report {
    let mut report = Report::default();
    let raw = report.as_bytes_mut();

    // version = 2 (matches AMD SNP spec format version)
    raw[0..4].copy_from_slice(&2u32.to_le_bytes());

    // sig_algo = 1 (ECDSA P-384 SHA-384, per AMD spec)
    raw[0x034..0x038].copy_from_slice(&1u32.to_le_bytes());

    // report_data: first 32 bytes = SHA-256(TLS pubkey DER), rest zeros
    raw[0x050..0x050 + 32].copy_from_slice(tls_pubkey_hash);

    // measurement
    raw[0x090..0x090 + MEASUREMENT_SIZE].copy_from_slice(measurement);

    // Sign the first SIGNED_REGION_SIZE bytes
    let signing_key = mock_signing_key();
    let signed_region: &[u8] = &raw[..SIGNED_REGION_SIZE];
    let sig: Signature = signing_key.sign(signed_region);
    let sig_bytes = sig.to_bytes(); // 96 bytes: R (48) || S (48)

    // Write R and S into the signature fields (left-justified within each 72-byte slot)
    raw[0x2A0..0x2A0 + 48].copy_from_slice(&sig_bytes[..48]);
    raw[0x2E8..0x2E8 + 48].copy_from_slice(&sig_bytes[48..]);

    report
}

/// Compute SHA-256 of a TLS public key DER (SubjectPublicKeyInfo encoding).
/// The result is what gets written into report_data[0..32].
pub fn tls_pubkey_hash(pubkey_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey_der);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_constructs_without_panic() {
        let _ = mock_signing_key();
    }

    #[test]
    fn mock_verifying_key_is_97_bytes() {
        let pk = mock_verifying_key_sec1();
        assert_eq!(pk.len(), 97, "uncompressed P-384 point = 1 + 48 + 48 bytes");
        assert_eq!(pk[0], 0x04, "uncompressed point prefix");
    }

    #[test]
    fn sign_produces_report_with_correct_fields() {
        let hash = [0x42_u8; 32];
        let measurement = [0xde_u8; MEASUREMENT_SIZE];
        let report = sign_mock_report(&hash, &measurement);
        assert_eq!(&report.report_data()[..32], &hash);
        assert_eq!(report.measurement(), &measurement);
        assert_eq!(report.version(), 2);
    }

    #[test]
    fn tls_pubkey_hash_is_deterministic() {
        let der = b"fake der bytes";
        assert_eq!(tls_pubkey_hash(der), tls_pubkey_hash(der));
    }
}
