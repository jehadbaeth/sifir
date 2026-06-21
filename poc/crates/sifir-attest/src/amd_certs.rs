/// AMD certificate chain verification — implemented in Phase 3.
///
/// This module handles verifying the VCEK certificate chain
/// (ARK → ASK → VCEK) used by real AMD SEV-SNP attestation reports.
/// It is a stub for Phases 1 and 2.
use p384::ecdsa::VerifyingKey;

use crate::verify::VerifyError;

/// Verify the AMD certificate chain and extract the VCEK public key.
///
/// `chain` is a slice of DER-encoded certificates: [VCEK, ASK, ARK].
/// The ARK is verified against the embedded AMD root key constant.
///
/// Phase 3 TODO: implement full chain verification.
pub fn vcek_verifying_key(chain: &[Vec<u8>]) -> Result<VerifyingKey, VerifyError> {
    if chain.is_empty() {
        return Err(VerifyError::CertChain(
            "AMD cert chain is empty (Phase 3 not yet implemented)".into(),
        ));
    }
    Err(VerifyError::CertChain(
        "AMD cert chain verification not yet implemented — use mock mode for Phases 1 and 2"
            .into(),
    ))
}
