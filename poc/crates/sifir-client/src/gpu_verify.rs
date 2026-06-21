/// NVIDIA GPU CC attestation JWT verification — Phase 4.
///
/// Verifies the GPU attestation JWT embedded in the RA-TLS cert extension.
///
/// # What is checked
/// - Nonce: `x-nvidia-attestation-nonce` must equal `hex(SHA-256(TLS_SPKI_DER))`.
///   This proves the GPU attestation is bound to this TLS session, not replayed.
/// - CC mode: `x-nvidia-cc-mode` claim must be present and equal "on".
/// - GPU model: `x-nvidia-gpu-model` is extracted and reported to the caller.
///
/// # What is NOT checked (production TODO, see DEVIATIONS.md D5)
/// - JWT signature against NVIDIA JWKS
///   (`https://nras.nvidia.com/.well-known/jwks.json`). Requires either the
///   `jsonwebtoken` crate (adds a duplicate `ring` dep) or the `rsa` crate plus
///   manual DER construction. The nonce binding already prevents cross-session
///   replay; add JWKS verification before any real deployment.
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct GpuClaims {
    pub gpu_model: String,
    pub cc_mode: String,
}

#[derive(Debug)]
pub enum GpuVerifyError {
    MalformedJwt(String),
    NonceMismatch { expected: String, got: String },
    CcModeNotOn { got: String },
    MissingClaim(String),
}

impl std::fmt::Display for GpuVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedJwt(e) => write!(f, "malformed JWT: {e}"),
            Self::NonceMismatch { expected, got } => {
                write!(f, "GPU JWT nonce mismatch: expected={expected}, got={got}")
            }
            Self::CcModeNotOn { got } => {
                write!(f, "GPU CC mode is not ON (got '{got}')")
            }
            Self::MissingClaim(c) => write!(f, "GPU JWT missing claim '{c}'"),
        }
    }
}

#[derive(Deserialize)]
struct NvidiaClaims {
    #[serde(rename = "x-nvidia-attestation-nonce")]
    nonce: Option<String>,
    #[serde(rename = "x-nvidia-cc-mode")]
    cc_mode: Option<String>,
    #[serde(rename = "x-nvidia-gpu-model")]
    gpu_model: Option<String>,
}

/// Verify the GPU attestation JWT from the RA-TLS cert extension.
///
/// `jwt`: the NRAS JWT string from `AttestationExtension::gpu_jwt`.
/// `tls_pubkey_der`: SPKI DER of the server's TLS certificate.
pub fn verify_gpu_jwt(
    jwt: &str,
    tls_pubkey_der: &[u8],
) -> Result<GpuClaims, GpuVerifyError> {
    // JWT format: header_b64url.payload_b64url.signature_b64url
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(GpuVerifyError::MalformedJwt(format!(
            "expected 3 parts, got {}",
            parts.len()
        )));
    }

    // Decode the payload (middle part).
    let payload_bytes = base64_url_decode(parts[1])
        .map_err(|e| GpuVerifyError::MalformedJwt(format!("payload decode: {e}")))?;

    let claims: NvidiaClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| GpuVerifyError::MalformedJwt(format!("payload JSON: {e}")))?;

    // 1. Verify nonce = hex(SHA-256(TLS_SPKI_DER)).
    let expected_nonce = hex::encode(Sha256::digest(tls_pubkey_der));
    let got_nonce = claims
        .nonce
        .ok_or_else(|| GpuVerifyError::MissingClaim("x-nvidia-attestation-nonce".into()))?;
    if got_nonce != expected_nonce {
        return Err(GpuVerifyError::NonceMismatch {
            expected: expected_nonce,
            got: got_nonce,
        });
    }

    // 2. Verify CC mode is "on".
    let cc_mode = claims
        .cc_mode
        .ok_or_else(|| GpuVerifyError::MissingClaim("x-nvidia-cc-mode".into()))?;
    if cc_mode.to_lowercase() != "on" {
        return Err(GpuVerifyError::CcModeNotOn { got: cc_mode });
    }

    // 3. Extract GPU model (informational).
    let gpu_model = claims
        .gpu_model
        .ok_or_else(|| GpuVerifyError::MissingClaim("x-nvidia-gpu-model".into()))?;

    Ok(GpuClaims { gpu_model, cc_mode })
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn make_jwt(nonce: &str, cc_mode: &str, gpu_model: &str) -> String {
        let header = r#"{"alg":"RS256","kid":"test"}"#;
        let payload = serde_json::json!({
            "x-nvidia-attestation-nonce": nonce,
            "x-nvidia-cc-mode": cc_mode,
            "x-nvidia-gpu-model": gpu_model,
        })
        .to_string();

        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{h}.{p}.fakesig")
    }

    fn expected_nonce(spki: &[u8]) -> String {
        hex::encode(Sha256::digest(spki))
    }

    #[test]
    fn valid_gpu_jwt_passes() {
        let spki = b"fake-spki-der";
        let nonce = expected_nonce(spki);
        let jwt = make_jwt(&nonce, "on", "H100");

        let claims = verify_gpu_jwt(&jwt, spki).unwrap();
        assert_eq!(claims.gpu_model, "H100");
        assert_eq!(claims.cc_mode, "on");
    }

    #[test]
    fn wrong_nonce_rejected() {
        let spki = b"fake-spki-der";
        let jwt = make_jwt("aabbcc", "on", "H100");
        let err = verify_gpu_jwt(&jwt, spki).unwrap_err();
        assert!(matches!(err, GpuVerifyError::NonceMismatch { .. }), "{err}");
    }

    #[test]
    fn cc_mode_off_rejected() {
        let spki = b"fake-spki-der";
        let nonce = expected_nonce(spki);
        let jwt = make_jwt(&nonce, "off", "H100");
        let err = verify_gpu_jwt(&jwt, spki).unwrap_err();
        assert!(matches!(err, GpuVerifyError::CcModeNotOn { .. }), "{err}");
    }

    #[test]
    fn malformed_jwt_rejected() {
        let err = verify_gpu_jwt("not.a.valid.jwt.parts", b"spki").unwrap_err();
        assert!(matches!(err, GpuVerifyError::MalformedJwt(_)), "{err}");
    }
}
