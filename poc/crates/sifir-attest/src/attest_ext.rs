/// Shared attestation extension type used by both server and client.
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::REPORT_SIZE;

/// Prototype OID — replace with a registered OID before production use.
pub const ATTEST_OID_STR: &str = "1.3.6.1.4.1.99999.1.1";

/// OID expressed as u64 arcs, for use with rcgen's CustomExtension API.
pub const ATTEST_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 1];

/// Payload of the custom X.509 extension embedded in the RA-TLS server certificate.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct AttestationExtension {
    /// Base64-encoded 1184-byte AMD SEV-SNP attestation report.
    pub report_b64: String,
    /// DER-encoded certificate chain [VCEK, ASK, ARK], each base64-encoded.
    /// Empty slice in mock mode.
    pub vcek_chain_b64: Vec<String>,
    /// Whether this is a mock or real attestation.
    pub mode: AttestationMode,
    /// Phase 4 only: NVIDIA GPU CC attestation JWT from NRAS. None in Phases 1–3.
    pub gpu_jwt: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum AttestationMode {
    Mock,
    AmdSevSnp,
}

impl AttestationExtension {
    /// Build a mock extension from a raw report.
    pub fn new_mock(report_bytes: &[u8; REPORT_SIZE]) -> Self {
        Self {
            report_b64: B64.encode(report_bytes),
            vcek_chain_b64: vec![],
            mode: AttestationMode::Mock,
            gpu_jwt: None,
        }
    }

    /// Build a real AMD SEV-SNP extension from a raw report and VCEK chain.
    /// `chain`: DER-encoded certs in order [VCEK, ASK, ARK].
    pub fn new_amd(report_bytes: &[u8; REPORT_SIZE], chain: &[Vec<u8>]) -> Self {
        Self {
            report_b64: B64.encode(report_bytes),
            vcek_chain_b64: chain.iter().map(|c| B64.encode(c)).collect(),
            mode: AttestationMode::AmdSevSnp,
            gpu_jwt: None,
        }
    }

    /// Builder: attach a NVIDIA GPU CC attestation JWT (Phase 4).
    /// Call after `new_mock()` or `new_amd()`.
    pub fn with_gpu_jwt(mut self, jwt: String) -> Self {
        self.gpu_jwt = Some(jwt);
        self
    }

    /// Serialise for embedding as the X.509 extension value bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("AttestationExtension serialisation is infallible")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(b)
    }

    /// Decode the report bytes.
    pub fn report_bytes(&self) -> anyhow::Result<[u8; REPORT_SIZE]> {
        let raw = B64.decode(&self.report_b64)?;
        raw.try_into()
            .map_err(|_| anyhow::anyhow!("report is not {} bytes", REPORT_SIZE))
    }

    /// Decode the VCEK chain as raw DER certificate bytes.
    pub fn vcek_chain_der(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        self.vcek_chain_b64
            .iter()
            .map(|b| B64.decode(b).map_err(Into::into))
            .collect()
    }
}
