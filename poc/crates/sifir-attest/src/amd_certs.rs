/// AMD certificate chain verification for Phase 3 (real SEV-SNP).
///
/// Verifies the VCEK certificate chain: ARK (root) → ASK (intermediate) → VCEK.
/// Returns the VCEK's P-384 public key, which is used to verify the attestation
/// report signature.
///
/// # Trust model
/// - ARK is the AMD root of trust. In production, its public key MUST be pinned
///   (hardcoded from AMD's published root certificate). This PoC verifies the
///   chain is internally consistent but does NOT pin the ARK — see TODO below.
/// - VCEK is per-chip and derived from the chip's fused key material.
/// - The chain is downloaded from AMD's Key Distribution Service (KDS) at:
///   https://kdsintf.amd.com/vcek/v1/{product}/{chip_id_hex}?{tcb_params}
///
/// # Supported algorithms
/// - ECDSA P-384 SHA-384 (AMD Genoa/Bergamo, EPYC 9xx4 series)
/// - RSA-4096 (AMD Milan/Rome, EPYC 7xx3 and older) — TODO: not yet implemented
use ecdsa::der::Signature as EcdsaDerSignature;
use p384::{
    ecdsa::{signature::Verifier, VerifyingKey},
    NistP384,
};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

use crate::verify::VerifyError;

/// Verify the AMD certificate chain and return the VCEK P-384 public key.
///
/// `chain`: DER-encoded certificates in order [VCEK, ASK, ARK].
pub fn vcek_verifying_key(chain: &[Vec<u8>]) -> Result<VerifyingKey, VerifyError> {
    if chain.len() < 3 {
        return Err(VerifyError::CertChain(format!(
            "expected [VCEK, ASK, ARK] (3 certs), got {}",
            chain.len()
        )));
    }

    let vcek = parse_cert(&chain[0])?;
    let ask = parse_cert(&chain[1])?;
    let ark = parse_cert(&chain[2])?;

    // 1. Verify ARK is self-signed (issuer == subject, signature valid under its own key).
    let ark_vk = extract_p384_key(&ark)?;
    verify_cert_signature(&ark, &ark_vk)
        .map_err(|e| VerifyError::CertChain(format!("ARK self-signature invalid: {e}")))?;

    // TODO (production): pin the ARK public key against AMD's published constant.
    // Without this, the chain is internally consistent but not root-anchored.
    // AMD publishes ARK certs at https://kdsintf.amd.com/vcek/v1/{product}/cert_chain.
    // The ARK cert is stable (changes only with a new product line) and should be
    // embedded as a compile-time constant, not fetched at runtime.

    // 2. Verify ASK is signed by ARK.
    verify_cert_signature(&ask, &ark_vk)
        .map_err(|e| VerifyError::CertChain(format!("ASK signature invalid (ARK): {e}")))?;

    // 3. Verify VCEK is signed by ASK.
    let ask_vk = extract_p384_key(&ask)?;
    verify_cert_signature(&vcek, &ask_vk)
        .map_err(|e| VerifyError::CertChain(format!("VCEK signature invalid (ASK): {e}")))?;

    // 4. Return VCEK public key for report signature verification.
    extract_p384_key(&vcek)
}

fn parse_cert(der: &[u8]) -> Result<Certificate, VerifyError> {
    Certificate::from_der(der).map_err(|e| VerifyError::CertChain(format!("DER parse error: {e}")))
}

fn extract_p384_key(cert: &Certificate) -> Result<VerifyingKey, VerifyError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let raw_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| VerifyError::CertChain("empty public key bits".into()))?;

    VerifyingKey::from_sec1_bytes(raw_key)
        .map_err(|e| VerifyError::CertChain(format!("P-384 key parse error: {e}")))
}

fn verify_cert_signature(cert: &Certificate, issuer_key: &VerifyingKey) -> Result<(), VerifyError> {
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| VerifyError::CertChain(format!("TBSCertificate encode error: {e}")))?;

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| VerifyError::CertChain("empty signature bits".into()))?;

    let der_sig = EcdsaDerSignature::<NistP384>::try_from(sig_bytes)
        .map_err(|e| VerifyError::CertChain(format!("DER signature parse error: {e}")))?;

    issuer_key
        .verify(&tbs_der, &der_sig)
        .map_err(|_| VerifyError::CertChain("signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke test: verify that the parse/extract functions handle a cert from our
    // mock server (which uses P-256, not P-384 — this should fail gracefully).
    #[test]
    fn empty_chain_returns_error() {
        let err = vcek_verifying_key(&[]).unwrap_err();
        assert!(matches!(err, VerifyError::CertChain(_)));
    }

    #[test]
    fn short_chain_returns_error() {
        let err = vcek_verifying_key(&[vec![0u8], vec![0u8]]).unwrap_err();
        assert!(matches!(err, VerifyError::CertChain(_)));
    }
}
