// AMD SEV-SNP Attestation Report field offsets and sizes.
// Source: AMD SEV-SNP ABI Specification, Rev 1.57, Table 22.

pub const REPORT_SIZE: usize = 1184;
pub const SIGNED_REGION_SIZE: usize = 0x2A0; // 672 bytes covered by the signature

// Field offsets
const OFF_VERSION: usize = 0x000;
const OFF_REPORT_DATA: usize = 0x050; // 80
const OFF_MEASUREMENT: usize = 0x090; // 144
const OFF_CHIP_ID: usize = 0x1A0; // 416
const OFF_SIG_R: usize = 0x2A0; // 672
const OFF_SIG_S: usize = 0x2E8; // 744

// Field sizes
pub const REPORT_DATA_SIZE: usize = 64;
pub const MEASUREMENT_SIZE: usize = 48;
pub const CHIP_ID_SIZE: usize = 64;

// Each signature component occupies 72 bytes in the AMD format.
// The actual P-384 scalar (48 bytes) is stored in the first 48 bytes;
// the remaining 24 bytes are zero padding.
// NOTE: This is the convention used by the mock signer. Verify against
// real AMD hardware in Phase 3 and adjust if needed.
pub const SIG_COMPONENT_FIELD: usize = 72;
pub const SIG_SCALAR_SIZE: usize = 48;

pub struct Report {
    raw: [u8; REPORT_SIZE],
}

impl Report {
    pub fn new(raw: [u8; REPORT_SIZE]) -> Self {
        Self { raw }
    }

    pub fn as_bytes(&self) -> &[u8; REPORT_SIZE] {
        &self.raw
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; REPORT_SIZE] {
        &mut self.raw
    }

    pub fn version(&self) -> u32 {
        u32::from_le_bytes(self.raw[OFF_VERSION..OFF_VERSION + 4].try_into().unwrap())
    }

    /// The 64-byte REPORT_DATA field.
    /// Convention: first 32 bytes = SHA-256(TLS public key DER), rest zeros.
    pub fn report_data(&self) -> &[u8; REPORT_DATA_SIZE] {
        self.raw[OFF_REPORT_DATA..OFF_REPORT_DATA + REPORT_DATA_SIZE]
            .try_into()
            .unwrap()
    }

    /// The 48-byte MEASUREMENT field (SHA-384 of initial VM memory in real SNP;
    /// arbitrary test bytes in mock mode).
    pub fn measurement(&self) -> &[u8; MEASUREMENT_SIZE] {
        self.raw[OFF_MEASUREMENT..OFF_MEASUREMENT + MEASUREMENT_SIZE]
            .try_into()
            .unwrap()
    }

    /// The 64-byte CHIP_ID field.
    pub fn chip_id(&self) -> &[u8; CHIP_ID_SIZE] {
        self.raw[OFF_CHIP_ID..OFF_CHIP_ID + CHIP_ID_SIZE]
            .try_into()
            .unwrap()
    }

    /// R scalar of the ECDSA signature (first SIG_SCALAR_SIZE bytes of the 72-byte field).
    pub fn sig_r(&self) -> &[u8; SIG_SCALAR_SIZE] {
        self.raw[OFF_SIG_R..OFF_SIG_R + SIG_SCALAR_SIZE]
            .try_into()
            .unwrap()
    }

    /// S scalar of the ECDSA signature (first SIG_SCALAR_SIZE bytes of the 72-byte field).
    pub fn sig_s(&self) -> &[u8; SIG_SCALAR_SIZE] {
        self.raw[OFF_SIG_S..OFF_SIG_S + SIG_SCALAR_SIZE]
            .try_into()
            .unwrap()
    }

    /// The region covered by the signature: bytes 0..SIGNED_REGION_SIZE.
    pub fn signed_region(&self) -> &[u8] {
        &self.raw[..SIGNED_REGION_SIZE]
    }

    /// Write R scalar (48 bytes) into the signature field.
    pub fn set_sig_r(&mut self, r: &[u8; SIG_SCALAR_SIZE]) {
        self.raw[OFF_SIG_R..OFF_SIG_R + SIG_SCALAR_SIZE].copy_from_slice(r);
    }

    /// Write S scalar (48 bytes) into the signature field.
    pub fn set_sig_s(&mut self, s: &[u8; SIG_SCALAR_SIZE]) {
        self.raw[OFF_SIG_S..OFF_SIG_S + SIG_SCALAR_SIZE].copy_from_slice(s);
    }
}

impl Default for Report {
    fn default() -> Self {
        Self {
            raw: [0u8; REPORT_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_region_ends_at_correct_offset() {
        assert_eq!(SIGNED_REGION_SIZE, 672);
    }

    #[test]
    fn total_size_matches_spec() {
        assert_eq!(REPORT_SIZE, 1184);
    }

    #[test]
    fn field_roundtrip() {
        let mut r = Report::default();
        let measurement = [0xab_u8; MEASUREMENT_SIZE];
        r.raw[OFF_MEASUREMENT..OFF_MEASUREMENT + MEASUREMENT_SIZE].copy_from_slice(&measurement);
        assert_eq!(r.measurement(), &measurement);
    }
}
