# Sifir PoC — Step-by-Step Implementation Plan

## What this PoC proves (and does not prove)

| Phase | Validates |
|---|---|
| 1 — RA-TLS mock (local) | Client verifies attestation before sending data; tampered measurement is rejected; X.509 binding works |
| 2 — Inference integration (local) | Full request path: verify → TLS → proxy → llama.cpp → response |
| 3 — Real CPU attestation (Azure DCasv5) | Real AMD SEV-SNP report is parseable and verifiable; RA-TLS works against genuine hardware TEE |
| 4 — GPU CC attestation (Azure NCC H100 v5) | GPU memory encryption is active; CPU+GPU attestation can be chained; performance overhead measured |

**What none of these phases prove**: multi-GPU inference confidentiality. H100 does not encrypt NVLink traffic between GPUs (Hopper limitation — fixed in Blackwell). Multi-GPU CC is unsupported on H100. Phase 4 validates single-GPU GPU CC. The full GLM-5.2 deployment (10× H100 + tensor parallelism) has a residual NVLink exposure documented in the threat model. This PoC establishes the RA-TLS + single-GPU GPU CC foundation.

---

## Repository structure

```
sifir/poc/
├── PLAN.md                     ← this file
├── Cargo.toml                  ← workspace root
├── crates/
│   ├── sifir-attest/           ← attestation parsing + verification (no_std compatible)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs          ← pub use all public types
│   │       ├── report.rs       ← AttestationReport struct (AMD spec, 1184 bytes)
│   │       ├── mock.rs         ← MockSigner: generate + sign fake reports with test P-384 key
│   │       ├── verify.rs       ← verify(): check sig, user_data binding, measurement
│   │       └── amd_certs.rs    ← AMD ARK/ASK/VCEK cert chain parsing + verification
│   ├── sifir-server/           ← RA-TLS gateway binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         ← startup: keygen, get attestation, start listeners
│   │       ├── tls.rs          ← rcgen cert with attestation as custom X.509 extension
│   │       ├── attest_ext.rs   ← AttestationExtension: serialize report + cert chain into DER
│   │       └── proxy.rs        ← forward /v1/generate to 127.0.0.1:8080
│   └── sifir-client/           ← RA-TLS client CLI binary
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs         ← parse CLI args, run verify → send → print
│           ├── verifier.rs     ← rustls ServerCertVerifier: extract ext, call sifir-attest
│           └── request.rs      ← send /v1/generate, stream response to stdout
└── inference/
    ├── server.py               ← FastAPI + llama-cpp-python on 127.0.0.1:8080
    └── requirements.txt
```

---

## Phase 1 — RA-TLS mock (local, no GPU, no cloud)

### Step 1.1 — Cargo workspace

`poc/Cargo.toml`:
```toml
[workspace]
members = [
    "crates/sifir-attest",
    "crates/sifir-server",
    "crates/sifir-client",
]
resolver = "2"
```

### Step 1.2 — sifir-attest crate

`poc/crates/sifir-attest/Cargo.toml`:
```toml
[package]
name = "sifir-attest"
version = "0.1.0"
edition = "2021"

[dependencies]
p384 = { version = "0.13", features = ["ecdsa"] }
sha2 = "0.10"
ecdsa = "0.16"
der = "0.7"
x509-cert = "0.2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"
thiserror = "1.0"
base64 = "0.22"

[dev-dependencies]
rand_core = { version = "0.6", features = ["getrandom"] }
```

**`report.rs`** — AMD SEV-SNP attestation report, exactly matching AMD spec revision 1.57 section 4.1:

```rust
#[repr(C, packed)]
pub struct AttestationReport {
    pub version:         u32,       // offset 0
    pub guest_svn:       u32,       // 4
    pub policy:          u64,       // 8
    pub family_id:       [u8; 16],  // 16
    pub image_id:        [u8; 16],  // 32
    pub vmpl:            u32,       // 48
    pub sig_algo:        u32,       // 52 — 1 = ECDSA P-384 SHA-384
    pub current_tcb:     u64,       // 56
    pub platform_info:   u64,       // 64
    pub flags:           u32,       // 72
    pub reserved0:       u32,       // 76
    pub report_data:     [u8; 64],  // 80 — first 32 bytes = SHA-256(TLS pubkey DER), rest zero
    pub measurement:     [u8; 48],  // 144 — SHA-384 of VM initial state
    pub host_data:       [u8; 32],  // 192
    pub id_key_digest:   [u8; 48],  // 224
    pub auth_key_digest: [u8; 48],  // 272
    pub report_id:       [u8; 32],  // 320
    pub report_id_ma:    [u8; 32],  // 352
    pub reported_tcb:    u64,       // 384
    pub reserved1:       [u8; 24],  // 392
    pub chip_id:         [u8; 64],  // 416
    pub committed_tcb:   u64,       // 480
    pub current_build:   u8,        // 488
    pub current_minor:   u8,        // 489
    pub current_major:   u8,        // 490
    pub reserved2:       u8,        // 491
    pub committed_build: u8,        // 492
    pub committed_minor: u8,        // 493
    pub committed_major: u8,        // 494
    pub reserved3:       u8,        // 495
    pub launch_tcb:      u64,       // 496
    pub reserved4:       [u8; 168], // 504
    // Signature covers bytes 0..672 above this line
    pub signature:       [u8; 512], // 672 — P-384 ECDSA: r (72 bytes) + s (72 bytes) + 368 bytes padding
}

pub const REPORT_SIZE: usize = 1184;
pub const SIGNED_REGION_SIZE: usize = 672;

impl AttestationReport {
    pub fn from_bytes(b: &[u8; REPORT_SIZE]) -> &Self {
        // SAFETY: packed repr, no padding, same size guaranteed by compile-time assert
        unsafe { &*(b.as_ptr() as *const AttestationReport) }
    }

    pub fn as_bytes(&self) -> &[u8; REPORT_SIZE] {
        unsafe { &*(self as *const AttestationReport as *const [u8; REPORT_SIZE]) }
    }

    pub fn signed_region(&self) -> &[u8] {
        &self.as_bytes()[..SIGNED_REGION_SIZE]
    }
}

const _: () = assert!(std::mem::size_of::<AttestationReport>() == REPORT_SIZE);
```

**`mock.rs`** — mock attestation using a test P-384 key baked into the binary:

The mock signing key is a P-384 key generated once and committed to the repo as a test fixture. The private key bytes are hardcoded in this file (this is intentional — it is a test key, not a secret).

Key functions to implement:
```rust
pub struct MockSigner;

impl MockSigner {
    // Returns (report_bytes, signing_cert_der)
    // report_data_prefix: first 32 bytes of report_data (use SHA-256(tls_pubkey_der))
    // measurement: 48-byte expected measurement (can be anything for mock)
    pub fn sign(
        report_data_prefix: &[u8; 32],
        measurement: &[u8; 48],
    ) -> ([u8; REPORT_SIZE], Vec<u8>);

    // The P-384 public key for verifying mock reports (DER encoded SubjectPublicKeyInfo)
    pub fn public_key_der() -> &'static [u8];
}
```

How to sign: fill in all fields with sensible defaults, set `report_data[0..32] = report_data_prefix`, set `measurement`, sign bytes `0..672` with P-384 ECDSA, write r+s into `signature[0..72]` and `signature[72..144]`.

**`verify.rs`** — verification logic:

```rust
pub enum AttestationKey {
    Mock,                           // verify against MockSigner::public_key_der()
    Amd { vcek_chain: Vec<Vec<u8>> }, // DER-encoded [VCEK, ASK, ARK]
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("signature invalid")]
    BadSignature,
    #[error("report_data does not match TLS public key: expected {expected}, got {got}")]
    KeyBindingMismatch { expected: String, got: String },
    #[error("measurement mismatch: expected {expected}, got {got}")]
    MeasurementMismatch { expected: String, got: String },
    #[error("cert chain verification failed: {0}")]
    CertChain(String),
}

pub fn verify(
    report_bytes: &[u8; REPORT_SIZE],
    key: &AttestationKey,
    expected_measurement: &[u8; 48],  // pass [0u8; 48] to skip measurement check (mock/dev mode)
    tls_pubkey_der: &[u8],            // DER-encoded SubjectPublicKeyInfo of the server's TLS cert
) -> Result<(), VerifyError>;
```

Verification steps inside `verify()`:
1. Cast `report_bytes` to `AttestationReport`
2. Compute `SHA-256(tls_pubkey_der)` → check equals `report.report_data[0..32]`
3. Compute `SHA-384(report.signed_region())` → this is the digest to verify
4. Verify the P-384 signature at `report.signature[0..144]` (r=`[0..72]`, s=`[72..144]`) against that digest using the appropriate public key
5. If `expected_measurement != [0u8; 48]`: check `report.measurement == expected_measurement`

**`amd_certs.rs`** — AMD cert chain (used in Phase 3):

```rust
// Download from: https://kdsintf.amd.com/vcek/v1/{product}/cert_chain
// product = "Milan" (EPYC 7xxx) or "Genoa" (EPYC 9xxx)
pub fn fetch_vcek_chain(chip_id: &[u8; 64], tcb: u64) -> Result<Vec<Vec<u8>>, Error>;

// Verify ARK (self-signed, check public key matches embedded constant) →
// ASK (verify ARK sig) → VCEK (verify ASK sig)
// Returns the VCEK public key (P-384) if chain is valid
pub fn verify_chain(chain: &[Vec<u8>]) -> Result<p384::PublicKey, Error>;
```

AMD ARK public key for Milan/Genoa must be hardcoded as a constant (it is a well-known AMD root key — fetch from AMD's website and embed). Do not fetch it at runtime; it is a trust anchor.

**Unit tests** (in `verify.rs`):
```rust
#[test]
fn mock_round_trip() {
    let tls_key = [1u8; 32]; // pretend SHA-256 of some TLS pubkey
    let measurement = [2u8; 48];
    let (report, _cert) = MockSigner::sign(&tls_key, &measurement);
    verify(&report, &AttestationKey::Mock, &measurement, ...).unwrap();
}

#[test]
fn tampered_measurement_rejected() {
    let (report, _cert) = MockSigner::sign(&[1u8; 32], &[2u8; 48]);
    let wrong_measurement = [3u8; 48];
    let err = verify(&report, &AttestationKey::Mock, &wrong_measurement, ...).unwrap_err();
    assert!(matches!(err, VerifyError::MeasurementMismatch { .. }));
}

#[test]
fn wrong_key_binding_rejected() {
    let (report, _cert) = MockSigner::sign(&[1u8; 32], &[2u8; 48]);
    // pass wrong TLS pubkey — SHA-256 won't match report_data
    let err = verify(&report, &AttestationKey::Mock, &[2u8; 48], ...).unwrap_err();
    assert!(matches!(err, VerifyError::KeyBindingMismatch { .. }));
}
```

Run with: `cargo test -p sifir-attest`

---

### Step 1.3 — sifir-server crate

`poc/crates/sifir-server/Cargo.toml`:
```toml
[package]
name = "sifir-server"
version = "0.1.0"
edition = "2021"

[dependencies]
sifir-attest = { path = "../sifir-attest" }
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["http1", "http2"] }
tower = "0.4"
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
rcgen = "0.13"
rustls = { version = "0.23", default-features = false, features = ["ring"] }
tokio-rustls = "0.26"
reqwest = { version = "0.12", features = ["json", "stream"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"
sha2 = "0.10"
thiserror = "1.0"
clap = { version = "4", features = ["derive"] }

[features]
real-attestation = []  # enables /dev/snp-guest ioctl path in amd_attestation.rs
```

**`attest_ext.rs`** — serialize/deserialize the X.509 extension payload:

```rust
// OID for Sifir attestation extension — prototype only, not a registered OID
// 1.3.6.1.4.1.99999.1.1
pub const SIFIR_ATTEST_OID: &str = "1.3.6.1.4.1.99999.1.1";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AttestationExtension {
    pub report_b64: String,              // base64(report_bytes[0..1184])
    pub vcek_chain_b64: Vec<String>,     // [base64(vcek_der), base64(ask_der), base64(ark_der)]
                                         // empty in mock mode — client uses MockSigner key
    pub mode: AttestationMode,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum AttestationMode {
    Mock,
    AmdSevSnp,
}

impl AttestationExtension {
    pub fn to_der_bytes(&self) -> Vec<u8>;   // JSON → UTF-8 bytes (DER OCTET STRING wrapper)
    pub fn from_der_bytes(b: &[u8]) -> Result<Self, Error>;
}
```

**`tls.rs`** — build the TLS server config:

```rust
// Returns (tls_config, cert_der_bytes, public_key_der_bytes)
// attestation_mode: Mock or AmdSevSnp
// inference_backend_url: e.g. "http://127.0.0.1:8080"
pub async fn build_tls_config(
    attestation_mode: AttestationMode,
) -> Result<(Arc<ServerConfig>, Vec<u8>, Vec<u8>), Error>;
```

Steps inside `build_tls_config`:
1. Generate P-256 keypair with `rcgen`
2. `pubkey_der = rcgen_keypair.public_key_raw_bytes()` (DER SubjectPublicKeyInfo)
3. `pubkey_hash = SHA-256(pubkey_der)` (32 bytes)
4. Get attestation report: if `Mock`, call `MockSigner::sign(&pubkey_hash, &[0u8; 48])`; if `AmdSevSnp`, call the ioctl (see Phase 3 stub)
5. Serialize `AttestationExtension` with the report
6. Build `rcgen::CertificateParams` with a custom extension at `SIFIR_ATTEST_OID`
7. Sign the cert with the keypair
8. Build `rustls::ServerConfig` using the cert + keypair
9. Return config + cert DER + pubkey DER

**`proxy.rs`** — forward requests to inference backend:

```rust
pub async fn proxy_generate(
    body: axum::body::Bytes,
    backend_url: &str,
) -> Result<axum::response::Response, Error>;
```

The proxy just forwards the JSON body to `{backend_url}/v1/generate` and streams the response back. Keep it simple — no transformation.

**`main.rs`** — startup:

```rust
#[derive(clap::Parser)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:7443")]
    listen: String,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    backend: String,
    #[arg(long, default_value = "false")]
    real_attestation: bool,
}
```

Startup sequence:
1. Parse args
2. `build_tls_config(mode)` → TLS config
3. Start axum router with one route: `POST /v1/generate → proxy_generate`
4. Wrap router in `tokio_rustls::TlsAcceptor`
5. Print `listening on tls://{listen}` and the server's expected measurement hex (for client config)

---

### Step 1.4 — sifir-client crate

`poc/crates/sifir-client/Cargo.toml`:
```toml
[package]
name = "sifir-client"
version = "0.1.0"
edition = "2021"

[dependencies]
sifir-attest = { path = "../sifir-attest" }
tokio = { version = "1", features = ["full"] }
rustls = { version = "0.23", default-features = false, features = ["ring"] }
tokio-rustls = "0.26"
reqwest = { version = "0.12", features = ["json", "stream", "rustls-tls"] }
clap = { version = "4", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"
sha2 = "0.10"
hex = "0.4"
thiserror = "1.0"
```

**`verifier.rs`** — custom rustls `ServerCertVerifier`:

```rust
pub struct AttestationVerifier {
    expected_measurement: [u8; 48],  // [0u8; 48] = skip measurement check
    mode: VerifierMode,
}

pub enum VerifierMode {
    Mock,
    AmdSevSnp,
}

impl rustls::client::ServerCertVerifier for AttestationVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer,
        intermediates: &[rustls::pki_types::CertificateDer],
        server_name: &rustls::pki_types::ServerName,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error>;
}
```

Steps inside `verify_server_cert`:
1. Parse `end_entity` as X.509 cert (using `x509-cert` crate)
2. Find extension with OID `SIFIR_ATTEST_OID`
3. Parse extension bytes as `AttestationExtension`
4. Decode `report_b64` → `[u8; 1184]`
5. Extract `pubkey_der` from the cert's SubjectPublicKeyInfo
6. Call `sifir_attest::verify(report_bytes, key, expected_measurement, pubkey_der)`
7. If `Ok(())` → return `Ok(ServerCertVerified::assertion())`
8. If `Err(e)` → print clear error and return `Err(rustls::Error::General(e.to_string()))`

**`request.rs`**:

```rust
pub async fn generate(
    client: &reqwest::Client,
    url: &str,
    prompt: &str,
    max_tokens: u32,
) -> Result<String, Error>;
```

**`main.rs`** CLI:

```rust
#[derive(clap::Parser)]
struct Args {
    /// Server address, e.g. sifir.example.com:7443
    #[arg(long)]
    server: String,

    /// Expected software measurement (48-byte hex). Use all-zeros to skip check.
    #[arg(long, default_value = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")]
    expected_measurement: String,

    /// Use mock attestation key instead of AMD key chain
    #[arg(long, default_value = "true")]
    mock: bool,

    /// Prompt to send
    prompt: String,
}
```

To validate: `cargo test -p sifir-client` — use a `tokio::test` that starts a mock server and verifies the client accepts valid attestation and rejects tampered measurement.

---

### Step 1.5 — Phase 1 integration test

Start a mock server in one terminal, run the client in another. No inference backend needed yet — the server can return a hardcoded response for this test.

```bash
# Terminal 1 — start server (mock attestation, no inference backend)
cargo run -p sifir-server -- --listen 127.0.0.1:7443 --backend http://127.0.0.1:8080

# Terminal 2 — run client
cargo run -p sifir-client -- --server 127.0.0.1:7443 --mock true "Hello"
```

Expected output: client prints attestation verification steps, then the response.

**Tamper test**: modify the expected measurement in the client to a wrong value — client must print `MeasurementMismatch` and exit non-zero.

---

## Phase 2 — Inference integration (local hardware)

The RTX 3070 (8GB) will run inference. The Mac handles the client.

### Step 2.1 — Inference server

`poc/inference/requirements.txt`:
```
fastapi==0.115.0
uvicorn[standard]==0.32.0
llama-cpp-python==0.3.4  # build with CUDA: CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python
```

`poc/inference/server.py`:

```python
from fastapi import FastAPI
from pydantic import BaseModel
from llama_cpp import Llama
import os

MODEL_PATH = os.environ["MODEL_PATH"]
llm = Llama(model_path=MODEL_PATH, n_gpu_layers=-1, n_ctx=4096)

app = FastAPI()

class GenerateRequest(BaseModel):
    prompt: str
    max_tokens: int = 512

class GenerateResponse(BaseModel):
    text: str
    tokens_used: int

@app.post("/v1/generate")
def generate(req: GenerateRequest) -> GenerateResponse:
    result = llm(req.prompt, max_tokens=req.max_tokens, echo=False)
    text = result["choices"][0]["text"]
    tokens_used = result["usage"]["completion_tokens"]
    return GenerateResponse(text=text, tokens_used=tokens_used)
```

### Step 2.2 — Download a test model

For the 3070 (8GB VRAM), use a small quantized model:

```bash
# Llama-3.2-3B-Instruct-Q4_K_M.gguf — ~2.0 GB, fits comfortably in 8GB
wget https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf
```

If running on Mac M3 instead of the 3070 (for initial testing), this model works with CPU+Metal offload.

### Step 2.3 — Start inference server (on desktop, 3070)

```bash
cd poc/inference
MODEL_PATH=/path/to/Llama-3.2-3B-Instruct-Q4_K_M.gguf uvicorn server:app --host 127.0.0.1 --port 8080
```

Quick smoke test: `curl -X POST http://127.0.0.1:8080/v1/generate -H 'Content-Type: application/json' -d '{"prompt": "Hello", "max_tokens": 50}'`

### Step 2.4 — Start RA-TLS server pointing at inference backend

```bash
cargo run -p sifir-server -- --listen 0.0.0.0:7443 --backend http://127.0.0.1:8080
```

### Step 2.5 — Connect from Mac (or other machine)

```bash
# On the Mac, against the desktop's IP
cargo run -p sifir-client -- --server 192.168.x.x:7443 --mock true "Write a haiku about cryptography"
```

Expected: attestation verified, response printed.

---

## Phase 3 — Real AMD SEV-SNP attestation (Azure DCasv5)

Target VM: `Standard_DCasv5` or `Standard_DC2as_v5` (~$0.10–$0.20/hr, SEV-SNP, no GPU)

### Step 3.1 — Add real attestation ioctl to sifir-server

Add `poc/crates/sifir-server/src/amd_attestation.rs` (only compiled with `--features real-attestation`):

```rust
use std::os::unix::io::RawFd;

const SNP_GET_REPORT: u64 = 0xc0304000; // ioctl number for /dev/snp-guest on Linux

#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64], // report_data field in the resulting report
    vmpl: u32,
    reserved: [u8; 28],
}

#[repr(C)]
struct SnpReportResp {
    status: u32,
    size: u32,
    reserved: [u8; 24],
    data: [u8; 1184],
}

pub fn get_attestation_report(user_data: &[u8; 64]) -> Result<[u8; 1184], Error> {
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/snp-guest")?;
    // ... ioctl call
    // Return the raw 1184-byte report
}
```

Additionally, fetch the VCEK cert chain from AMD KDS using the chip_id from the report:

```rust
pub async fn fetch_vcek_chain(
    chip_id: &[u8; 64],
    tcb: u64,
    product: &str, // "Milan" or "Genoa"
) -> Result<Vec<Vec<u8>>, Error> {
    // GET https://kdsintf.amd.com/vcek/v1/{product}/{chip_id_hex}?blSPL=...&teeSPL=...
    // Returns PEM bundle: VCEK cert + ASK cert + ARK cert
}
```

In `tls.rs`, update `build_tls_config` to call these when `real-attestation` feature is on.

### Step 3.2 — Update sifir-client for AMD key path

In `verifier.rs`, when `mode == AmdSevSnp`:
1. Parse `vcek_chain_b64` from the extension
2. Call `sifir_attest::amd_certs::verify_chain(&vcek_chain)` → get VCEK public key
3. Verify the AMD ARK is the expected key (hardcoded constant — this is the trust anchor)
4. Verify the report signature using the VCEK key
5. Check report_data binding and measurement as before

### Step 3.3 — Provision Azure DCasv5

```bash
# Create VM (one-time)
az vm create \
  --resource-group sifir-poc \
  --name sifir-poc-cpu \
  --image "Canonical:ubuntu-24_04-lts:server:latest" \
  --size Standard_DC2as_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username azureuser \
  --generate-ssh-keys

# Verify SEV-SNP is active
ssh azureuser@<ip> "dmesg | grep -i sev"
# Should show: AMD Secure Encrypted Virtualization (SEV-SNP) enabled
```

### Step 3.4 — Deploy and test

```bash
# Build on the VM
cargo build --release -p sifir-server --features real-attestation

# Start server (no inference backend — use a stub for Phase 3 CPU test)
./target/release/sifir-server --listen 0.0.0.0:7443 --backend http://127.0.0.1:8080

# From your Mac — note: NOT --mock, now using AMD key path
cargo run -p sifir-client -- \
  --server <vm_ip>:7443 \
  --mock false \
  --expected-measurement 000000000000...  # zeros = skip measurement check first
  "Hello"
```

**Measurement check test**: once connected, read the actual measurement from the output, then pass it as `--expected-measurement`. Verify it passes. Then modify one bit — verify the client rejects it.

**Estimated cost**: 2 hours on `Standard_DC2as_v5` ≈ $0.40. Stop the VM after testing.

---

## Phase 4 — GPU Confidential Computing (Azure NCC H100 v5)

Target VM: `Standard_NCC40ads_H100_v5` (~$8.90/hr, spot ~$1.65/hr)

This is a single H100 (94GB VRAM) with GPU CC mode active by default. The goal is to validate the GPU attestation chain and measure overhead.

### Step 4.1 — Provision NCC H100 v5

```bash
az vm create \
  --resource-group sifir-poc \
  --name sifir-poc-gpu \
  --image "Canonical:ubuntu-24_04-lts:server:latest" \
  --size Standard_NCC40ads_H100_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username azureuser \
  --generate-ssh-keys

# Verify CC mode
ssh azureuser@<ip> "nvidia-smi -q | grep -i 'Confidential'"
# Should show: Confidential Compute : Enabled
```

### Step 4.2 — Install NVIDIA attestation SDK

```bash
pip install nv-attestation-sdk
```

This SDK fetches GPU attestation evidence and verifies it against NVIDIA's Remote Attestation Service (NRAS).

### Step 4.3 — Add GPU attestation module to sifir-server

Add `poc/crates/sifir-server/src/gpu_attestation.rs` (only compiled with `--features gpu-cc`):

```rust
// Calls out to a Python sidecar script to get the NRAS JWT
// (NVIDIA's SDK is Python-only; calling it from Rust via subprocess is simpler than FFI)
pub async fn get_gpu_attestation_jwt(tls_pubkey_hash: &[u8; 32]) -> Result<String, Error>;

// Returns the raw NVIDIA attestation evidence (for client-side verification)
pub async fn get_raw_gpu_evidence() -> Result<GpuEvidence, Error>;
```

The Python sidecar (`poc/inference/gpu_attest.py`):
```python
import nv_attestation_sdk.attestation as nv_attest
import sys, json, base64

# nonce ties the attestation to our TLS session
nonce = sys.argv[1]  # hex of SHA-256(tls_pubkey_der)

client = nv_attest.Attestation()
client.set_name("sifir-poc")
client.set_nonce(bytes.fromhex(nonce))
client.add_evidence_service(nv_attest.EvidenceService.LOCAL)
client.set_verifier(nv_attest.RootOfTrust.GPU, nv_attest.Verifier.OCSP)

ok, token = client.attest()
print(json.dumps({"ok": ok, "token": token}))
```

### Step 4.4 — Extend AttestationExtension for GPU

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AttestationExtension {
    pub report_b64: String,
    pub vcek_chain_b64: Vec<String>,
    pub mode: AttestationMode,
    pub gpu_jwt: Option<String>,  // NRAS JWT — present when GPU CC is active
}
```

### Step 4.5 — Extend sifir-client to verify GPU JWT

In `verifier.rs`, if `gpu_jwt` is present:

```rust
fn verify_gpu_jwt(jwt: &str) -> Result<GpuClaims, Error> {
    // 1. Parse JWT header — get kid (NVIDIA signing key ID)
    // 2. Fetch NVIDIA's JWKS from https://nras.nvidia.com/.well-known/jwks.json
    //    (or use a cached copy embedded in the binary — better for offline use)
    // 3. Verify JWT signature with matching key
    // 4. Parse claims and return
}

pub struct GpuClaims {
    pub gpu_model: String,           // e.g. "H100"
    pub cc_enabled: bool,
    pub driver_version: String,
    pub vbios_version: String,
}
```

**The GPU JWT nonce must match**: the JWT's nonce claim must equal `hex(SHA-256(tls_pubkey_der))`. This proves the GPU attestation is bound to this specific TLS session, not replayed from a different session.

### Step 4.6 — Inference test on H100

Download a model that fits in 94GB:
```bash
# Llama-3.1-70B-Instruct at FP8 (~70GB) — fits with headroom
# Or Qwen2.5-72B-Instruct-Q4_K_M.gguf (~41GB) for llama.cpp
wget https://huggingface.co/bartowski/Qwen2.5-72B-Instruct-GGUF/resolve/main/Qwen2.5-72B-Instruct-Q4_K_M.gguf
```

### Step 4.7 — Measure overhead

Run the same inference benchmark with CC mode enabled, then disabled (two runs of 100 requests, 200 tokens each). Record:
- Tokens/sec
- Time-to-first-token
- Total throughput

Expected per literature: ~5% overhead for 70B-class models (compute-dominated, PCIe overhead is small fraction of total).

### Step 4.8 — Validate full chain

The client should now print:
```
[✓] AMD SEV-SNP attestation verified (VCEK chain valid, measurement matches)
[✓] GPU CC attestation verified (H100, CC enabled, driver vX.X.X, VBIOS vX.X.X)
[✓] TLS session bound to both attestations (nonce matches)
Sending request...
Response: ...
```

**Estimated cost**: 2 hours on spot NCC H100 v5 ≈ $3.30 at spot pricing. Budget $10 for retries.

---

## Implementation order (critical path)

```
1. sifir-attest: report.rs + mock.rs + verify.rs
2. Unit tests pass (cargo test -p sifir-attest)
3. sifir-server: tls.rs (rcgen cert with extension) + main.rs stub
4. sifir-client: verifier.rs + main.rs
5. Phase 1 integration test (no inference backend)
6. inference/server.py + llama.cpp install
7. Phase 2 integration test (real inference)
8. amd_certs.rs + amd_attestation.rs (ioctl)
9. Azure DCasv5 deploy → Phase 3 test
10. gpu_attestation.rs + GPU JWT verification
11. Azure NCC H100 v5 deploy → Phase 4 test
```

---

## Key constants and configuration

| Constant | Value | Where |
|---|---|---|
| Sifir attestation OID | `1.3.6.1.4.1.99999.1.1` | `sifir-server/src/attest_ext.rs` |
| AMD ARK Milan public key | Embed from AMD's published ARK | `sifir-attest/src/amd_certs.rs` |
| AMD ARK Genoa public key | Embed from AMD's published ARK | `sifir-attest/src/amd_certs.rs` |
| AMD KDS URL | `https://kdsintf.amd.com/vcek/v1/{product}/{chip_id_hex}` | `sifir-attest/src/amd_certs.rs` |
| NRAS JWKS URL | `https://nras.nvidia.com/.well-known/jwks.json` | `sifir-client/src/verifier.rs` |
| RA-TLS server port | `7443` | default in server args |
| Inference backend port | `8080` | default in server args |
| Signed region size | `672` bytes | `sifir-attest/src/report.rs` |
| Report total size | `1184` bytes | `sifir-attest/src/report.rs` |

---

## Open NVLink limitation

H100 does not encrypt NVLink traffic between GPUs. The NVLink firewall prevents peer GPU memory reads, but a physical bus tap would expose inter-GPU activations. This is a Hopper limitation — Blackwell (B200/GB200) adds hardware NVLink encryption.

For the full GLM-5.2 deployment (10× H100, tensor parallelism), this is the primary residual risk in T1. It is documented in `docs/threat-model.md`. The PoC validates single-GPU CC only. The multi-GPU confidentiality story for H100 relies on the NVLink firewall (logical isolation) and the implausibility of a physical bus tap at a real colo facility — not cryptographic encryption.

Groups with a threat model that requires full encryption of inter-GPU traffic must wait for Blackwell hardware availability.

---

## Definition of done

Phase 1: `cargo test --workspace` passes. Client rejects tampered measurement.

Phase 2: Client talks to 3070-backed inference server through RA-TLS. Response is printed. Latency under 30 seconds for a 200-token response.

Phase 3: Client connects to Azure DCasv5, AMD SEV-SNP attestation verified using real VCEK chain. Client rejects connection when expected measurement is wrong.

Phase 4: Client connects to Azure NCC H100 v5, CPU + GPU attestation both verified. GPU CC claims parsed from JWT. Nonce binding confirmed. Inference produces a valid response. Overhead measured.
