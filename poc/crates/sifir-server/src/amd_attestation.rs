//! Real AMD SEV-SNP attestation via /dev/snp-guest ioctl.
//!
//! Only compiled when `--features real-attestation` is set. Requires:
//!   - Linux 5.19+ kernel with `sev_guest` driver
//!   - Running inside an AMD SEV-SNP VM (Azure DCasv5 / NCC H100 v5)
//!   - `/dev/snp-guest` device accessible
//!
//! Flow:
//!   1. ioctl on /dev/snp-guest → 1184-byte attestation report
//!   2. Extract chip_id and TCB version from the report
//!   3. Fetch VCEK DER from AMD KDS (per-chip cert, binds chip_id + TCB)
//!   4. Fetch ARK + ASK PEM bundle from AMD KDS (stable root/intermediate chain)
//!   5. Return (report_bytes, [vcek_der, ask_der, ark_der])

use anyhow::{bail, Context};

// ────────────────────────────────────────────────────────────────────────────
// Linux kernel ioctl interface (include/uapi/linux/sev-guest.h)
// ────────────────────────────────────────────────────────────────────────────

/// Matches `snp_report_req` from the kernel header.
/// user_data (64B) goes into report_data[0..64] of the attestation report.
#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    _rsvd: [u8; 28],
}

/// Matches `snp_report_resp` (4000 bytes).
/// data[0..1184] is the attestation report; the rest is padding.
#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

/// Matches `snp_guest_request_ioctl`.
/// Uses raw pointers; only valid while SnpReportReq / SnpReportResp are live.
#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// `_IOWR('+', 0, snp_guest_request_ioctl)` where sizeof = 32.
/// Direction = READ|WRITE (3), size = 32, type = '+' (0x2B), nr = 0.
const SNP_GET_REPORT: u64 = (3u64 << 30) | (32u64 << 16) | (0x2B_u64 << 8);

const SNP_DEVICE: &str = "/dev/snp-guest";
const REPORT_SIZE: usize = sifir_attest::REPORT_SIZE;

// ────────────────────────────────────────────────────────────────────────────
// AMD KDS (Key Distribution Service) constants
// ────────────────────────────────────────────────────────────────────────────

const KDS_BASE: &str = "https://kdsintf.amd.com/vcek/v1";

// Offsets into the 1184-byte attestation report (AMD SEV-SNP spec, Table 22).
// These are the reported_tcb (8 bytes) and chip_id (64 bytes) fields.
const OFF_REPORTED_TCB: usize = 0x038; // 56
const OFF_CHIP_ID: usize = 0x188; // 392
const CHIP_ID_LEN: usize = 64;

// TCB_VERSION byte layout (little-endian packed u64):
//   byte 0: bl_spl
//   byte 1: tee_spl
//   bytes 2-5: reserved
//   byte 6: snp_spl
//   byte 7: ucode_spl
struct TcbVersion {
    bl_spl: u8,
    tee_spl: u8,
    snp_spl: u8,
    ucode_spl: u8,
}

impl TcbVersion {
    fn from_report(report: &[u8; REPORT_SIZE]) -> Self {
        let raw = &report[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8];
        TcbVersion {
            bl_spl: raw[0],
            tee_spl: raw[1],
            snp_spl: raw[6],
            ucode_spl: raw[7],
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// Fetch a real AMD SEV-SNP attestation report and the VCEK cert chain.
///
/// `user_data`: 64 bytes placed in report_data[0..64]. Pass the SHA-256 of
///              the TLS SPKI in the first 32 bytes (RA-TLS binding).
///
/// `product`: AMD product name for KDS lookup. Valid values: "Milan",
///            "Genoa", "Bergamo", "Genoa", "Turin". Azure DCasv5 uses "Milan".
///
/// Returns `(report_bytes, [vcek_der, ask_der, ark_der])`.
pub async fn get_report_and_chain(
    user_data: [u8; 64],
    product: &str,
) -> anyhow::Result<([u8; REPORT_SIZE], Vec<Vec<u8>>)> {
    let report = get_snp_report(user_data)?;
    let chain = fetch_vcek_chain(&report, product).await?;
    Ok((report, chain))
}

// ────────────────────────────────────────────────────────────────────────────
// ioctl implementation
// ────────────────────────────────────────────────────────────────────────────

fn get_snp_report(user_data: [u8; 64]) -> anyhow::Result<[u8; REPORT_SIZE]> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(SNP_DEVICE)
        .with_context(|| format!("open {SNP_DEVICE} (must run inside AMD SEV-SNP VM)"))?;

    let mut req = SnpReportReq {
        user_data,
        vmpl: 0, // VMPL0 = guest OS level
        _rsvd: [0u8; 28],
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut _ as u64,
        resp_data: &mut resp as *mut _ as u64,
        exitinfo2: 0,
    };

    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            SNP_GET_REPORT as libc::c_ulong,
            &mut ioctl_req as *mut _,
        )
    };

    if rc != 0 {
        let err = std::io::Error::last_os_error();
        bail!("SNP_GET_REPORT ioctl failed (errno {rc}): {err}");
    }

    if ioctl_req.exitinfo2 != 0 {
        bail!(
            "SNP_GET_REPORT firmware error: exitinfo2=0x{:016x}",
            ioctl_req.exitinfo2
        );
    }

    // The first REPORT_SIZE bytes of resp.data are the attestation report.
    let mut report = [0u8; REPORT_SIZE];
    report.copy_from_slice(&resp.data[..REPORT_SIZE]);
    Ok(report)
}

// ────────────────────────────────────────────────────────────────────────────
// KDS cert chain fetch
// ────────────────────────────────────────────────────────────────────────────

async fn fetch_vcek_chain(
    report: &[u8; REPORT_SIZE],
    product: &str,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let chip_id_hex = hex::encode(&report[OFF_CHIP_ID..OFF_CHIP_ID + CHIP_ID_LEN]);
    let tcb = TcbVersion::from_report(report);

    // Fetch VCEK (per-chip, DER)
    let vcek_url = format!(
        "{KDS_BASE}/{product}/{chip_id_hex}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        tcb.bl_spl, tcb.tee_spl, tcb.snp_spl, tcb.ucode_spl
    );

    // Fetch ARK + ASK bundle (PEM, stable per product line)
    let chain_url = format!("{KDS_BASE}/{product}/cert_chain");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build reqwest client")?;

    let vcek_der = client
        .get(&vcek_url)
        .send()
        .await
        .with_context(|| format!("GET {vcek_url}"))?
        .error_for_status()
        .with_context(|| format!("KDS VCEK fetch failed: {vcek_url}"))?
        .bytes()
        .await
        .context("read VCEK response body")?
        .to_vec();

    let chain_pem = client
        .get(&chain_url)
        .send()
        .await
        .with_context(|| format!("GET {chain_url}"))?
        .error_for_status()
        .with_context(|| format!("KDS cert_chain fetch failed: {chain_url}"))?
        .text()
        .await
        .context("read cert_chain response body")?;

    // Parse the PEM bundle into individual DER certs.
    // cert_chain endpoint returns [ASK, ARK] concatenated PEM.
    let pem_certs = parse_pem_bundle(&chain_pem).context("parse cert_chain PEM bundle")?;

    if pem_certs.len() < 2 {
        bail!(
            "expected at least 2 certs in KDS cert_chain, got {}",
            pem_certs.len()
        );
    }

    // KDS cert_chain returns ASK first, ARK second (per AMD documentation).
    // Our verify chain expects [VCEK, ASK, ARK].
    let ask_der = pem_certs[0].clone();
    let ark_der = pem_certs[1].clone();

    Ok(vec![vcek_der, ask_der, ark_der])
}

/// Parse a PEM bundle (multiple concatenated PEM blocks) into DER bytes.
fn parse_pem_bundle(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            if !in_cert {
                bail!("unexpected END CERTIFICATE");
            }
            in_cert = false;
            use base64::Engine as _;
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64.as_str())
                .context("base64 decode PEM cert")?;
            certs.push(der);
        } else if in_cert && !trimmed.is_empty() {
            b64.push_str(trimmed);
        }
    }

    if in_cert {
        bail!("unterminated PEM cert block");
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pem_bundle_single() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let certs = parse_pem_bundle(pem).unwrap();
        assert_eq!(certs, vec![b"hello".to_vec()]);
    }

    #[test]
    fn parse_pem_bundle_two_certs() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nd29ybGQ=\n-----END CERTIFICATE-----\n";
        let certs = parse_pem_bundle(pem).unwrap();
        assert_eq!(certs[0], b"hello");
        assert_eq!(certs[1], b"world");
    }

    #[test]
    fn parse_pem_bundle_empty() {
        let certs = parse_pem_bundle("").unwrap();
        assert!(certs.is_empty());
    }
}
