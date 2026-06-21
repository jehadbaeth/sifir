# Sifir PoC — Testing Guide

This document explains exactly how to test every phase of the PoC, from a local mock run on any laptop to a full CPU+GPU confidential attestation on Azure.

**Jump to:**
- [Prerequisites](#prerequisites)
- [Phase 1 — Mock attestation (local)](#phase-1--mock-attestation-local)
- [Phase 2 — Inference server with real GPU (local)](#phase-2--inference-server-local)
- [Phase 3 — Real AMD SEV-SNP on Azure DCasv5](#phase-3--amd-sev-snp-azure-dcasv5)
- [Phase 4 — GPU CC on Azure NCC H100 v5](#phase-4--gpu-cc-azure-ncc-h100-v5)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Local (all phases)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Build the workspace (run from poc/)
cd poc/
cargo build
```

### Azure CLI (Phases 3 and 4)

```bash
brew install azure-cli          # macOS
# or: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  # Ubuntu

az login
az account set --subscription "<your-subscription-id>"
```

---

## Phase 1 — Mock attestation (local)

**What this tests:** The full RA-TLS handshake — server generates a self-signed TLS
cert containing a mock attestation report, client verifies the report before
sending any request data. No AMD hardware required.

### Start the server (terminal 1)

```bash
cd poc/
cargo run -p sifir-server -- --listen 127.0.0.1:7443
```

Expected output:
```
[sifir-server] building TLS setup (mock attestation)...
[sifir-server] measurement: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
[sifir-server] listening on https://127.0.0.1:7443
[sifir-server] no backend configured — echo mode active
```

### Run the client (terminal 2)

```bash
cd poc/
cargo run -p sifir-client -- --server 127.0.0.1:7443 "hello sifir"
```

Expected output (stderr):
```
[client] WARNING: measurement check disabled (expected = all-zeros)
[client] connecting to https://127.0.0.1:7443
[client] CPU attestation verified (AMD SEV-SNP / mock)
[client] attestation verified successfully
```

Expected output (stdout):
```
[mock inference] echo: hello sifir
```

### Test measurement rejection

This verifies the client refuses a server whose measurement doesn't match.

```bash
cargo run -p sifir-client -- \
  --server 127.0.0.1:7443 \
  --expected-measurement aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "hello"
```

Expected: TLS handshake fails with `measurement mismatch` error. Exit code 1.
The client never sends the prompt — it rejects before any data is transmitted.

---

## Phase 2 — Inference server local

**What this tests:** The full stack including real LLM inference. Requires a CUDA GPU
(tested on RTX 3070) and a downloaded GGUF model.

### Download a model

For a quick test use a small GGUF:

```bash
# ~4GB download: Mistral 7B Q4
wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf \
  -O /tmp/mistral-7b.gguf
```

### Install inference dependencies

```bash
cd poc/inference/
python3 -m venv .venv && source .venv/bin/activate

# CUDA build (RTX 3070):
CMAKE_ARGS="-DGGML_CUDA=on" pip install -r requirements.txt
```

### Start the inference server (terminal 1)

```bash
cd poc/inference/
source .venv/bin/activate
MODEL_PATH=/tmp/mistral-7b.gguf python server.py
```

Expected: model loads and `listening on 127.0.0.1:8080` is printed.

### Start the RA-TLS gateway (terminal 2)

```bash
cd poc/
cargo run -p sifir-server -- \
  --listen 127.0.0.1:7443 \
  --backend http://127.0.0.1:8080
```

### Run the client (terminal 3)

```bash
cd poc/
cargo run -p sifir-client -- \
  --server 127.0.0.1:7443 \
  --max-tokens 64 \
  "What is confidential computing?"
```

Expected: attestation verified on stderr, LLM response on stdout.

---

## Phase 3 — AMD SEV-SNP on Azure DCasv5

**What this tests:** Real hardware attestation. The server fetches an actual
AMD attestation report from `/dev/snp-guest`, downloads the VCEK cert chain
from AMD KDS, and embeds both in the TLS cert. The client verifies the full
AMD cert chain (ARK → ASK → VCEK) and the report signature.

> **Known limitation (D6):** Azure DCasv5 uses AMD Milan CPUs with RSA-4096
> cert chains. The current `amd_certs.rs` only supports ECDSA P-384 (Genoa).
> Phase 3 will succeed only if run on a Genoa-based VM, or after adding `rsa`
> crate support (see `DEVIATIONS.md D6`). Azure NCC H100 v5 (Phase 4) uses
> Genoa and works directly.

### Provision the Azure VM

```bash
az group create --name sifir-poc --location eastus

az vm create \
  --resource-group sifir-poc \
  --name sifir-poc-cpu \
  --image Canonical:ubuntu-24_04-lts:server:latest \
  --size Standard_DC2as_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --enable-secure-boot true \
  --admin-username azureuser \
  --generate-ssh-keys

VM_IP=$(az vm show --resource-group sifir-poc --name sifir-poc-cpu \
  --show-details --query publicIps -o tsv)
```

### Set up the VM

```bash
ssh azureuser@$VM_IP

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Clone the repo
git clone <sifir-repo-url> sifir
cd sifir/poc/

# Verify /dev/snp-guest exists
ls -la /dev/snp-guest
# Expected: crw------- 1 root root 10, 126 ...

# If missing, enable it:
sudo modprobe sev-guest
```

### Build with real attestation

```bash
cd ~/sifir/poc/
cargo build -p sifir-server --release --features real-attestation
```

### Open the firewall port

```bash
# From your local machine:
az vm open-port --resource-group sifir-poc --name sifir-poc-cpu --port 7443
```

### Start the server on the Azure VM

```bash
# On the Azure VM:
cd ~/sifir/poc/
./target/release/sifir-server \
  --listen 0.0.0.0:7443 \
  --amd \
  --snp-product Milan
```

Expected startup:
```
[sifir-server] building TLS setup (AMD SEV-SNP, product=Milan)...
[sifir-server] fetching AMD SNP attestation report...
[sifir-server] measurement: <48-byte hex>
[sifir-server] listening on https://0.0.0.0:7443
```

Note the measurement hex — you'll use it for verified connections.

### Run the client (from your local machine)

```bash
# First: connect with zero measurement (skip check, verify the mechanism works)
cargo run -p sifir-client -- \
  --server $VM_IP:7443 \
  --amd \
  "hello sifir"

# Then: connect with the real measurement (full verification)
cargo run -p sifir-client -- \
  --server $VM_IP:7443 \
  --amd \
  --expected-measurement <measurement-from-server-startup> \
  "hello sifir"
```

Expected (stderr):
```
[client] CPU attestation verified (AMD SEV-SNP / mock)
[client] attestation verified successfully
```

### Verify the measurement doesn't change across restarts

Each restart generates a new TLS keypair (measurement stays the same — it's the
software hash). Confirm:

```bash
# Restart the server and check the measurement is identical
./target/release/sifir-server --listen 0.0.0.0:7443 --amd --snp-product Milan
# measurement: <same hex as before>
```

### Clean up

```bash
az group delete --name sifir-poc --yes --no-wait
```

---

## Phase 4 — GPU CC on Azure NCC H100 v5

**What this tests:** CPU attestation (AMD SEV-SNP) chained with GPU CC attestation
(NVIDIA H100). Both are embedded in the single TLS cert. The client verifies the
nonce binding between the GPU JWT and the TLS session.

> **Single-GPU only.** H100 NVLink traffic is NOT encrypted (Hopper limitation).
> This phase validates single-GPU CC. See `DEVIATIONS.md D5` for the GPU JWT
> signature verification limitation.

### Provision the Azure NCC H100 v5 VM

```bash
az group create --name sifir-poc-gpu --location eastus

az vm create \
  --resource-group sifir-poc-gpu \
  --name sifir-poc-gpu \
  --image Canonical:ubuntu-24_04-lts:server:latest \
  --size Standard_NCC40ads_H100_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --enable-secure-boot true \
  --admin-username azureuser \
  --generate-ssh-keys

GPU_IP=$(az vm show --resource-group sifir-poc-gpu --name sifir-poc-gpu \
  --show-details --query publicIps -o tsv)
```

### Set up the VM

```bash
ssh azureuser@$GPU_IP

# Install NVIDIA drivers (CC-enabled)
sudo apt-get update && sudo apt-get install -y nvidia-utils-550
sudo reboot

# After reboot:
ssh azureuser@$GPU_IP

# Verify H100 CC mode
nvidia-smi --query-gpu=name,cc_mode --format=csv,noheader
# Expected: NVIDIA H100 NVL, ON

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Clone the repo
git clone <sifir-repo-url> sifir
cd sifir/poc/

# Install Python dependencies (for gpu_attest.py)
python3 -m venv inference/.venv
source inference/.venv/bin/activate
pip install nv-attestation-sdk>=1.4.0

# Build with all features
cargo build -p sifir-server --release --features real-attestation,gpu-cc
```

### Open the firewall port

```bash
az vm open-port --resource-group sifir-poc-gpu --name sifir-poc-gpu --port 7443
```

### Start the server

```bash
# On the GPU VM:
cd ~/sifir/poc/
source inference/.venv/bin/activate

./target/release/sifir-server \
  --listen 0.0.0.0:7443 \
  --amd \
  --snp-product Genoa \
  --gpu-cc \
  --gpu-attest-script ~/sifir/poc/inference/gpu_attest.py
```

Expected startup:
```
[sifir-server] building TLS setup (AMD SEV-SNP + GPU CC, product=Genoa)...
[sifir-server] fetching AMD SNP attestation report...
[sifir-server] fetching GPU CC attestation JWT...
[sifir-server] measurement: <48-byte hex>
[sifir-server] listening on https://0.0.0.0:7443
```

### Run the client with GPU CC verification

```bash
# From your local machine:
cargo run -p sifir-client -- \
  --server $GPU_IP:7443 \
  --amd \
  --gpu-cc \
  "test gpu confidential computing"
```

Expected (stderr):
```
[client] CPU attestation verified (AMD SEV-SNP / mock)
[client] GPU attestation verified: model=H100, cc_mode=on
[client] attestation verified successfully
```

### Test GPU CC mode enforcement

To confirm `--gpu-cc` rejects a server without GPU attestation:

```bash
# Start a mock server (no GPU JWT):
cargo run -p sifir-server -- --listen 127.0.0.1:7443

# Client with --gpu-cc fails:
cargo run -p sifir-client -- --server 127.0.0.1:7443 --gpu-cc "test"
# Expected: TLS error: --gpu-cc set but server cert has no GPU JWT
```

### Connect the inference server (full Phase 4 stack)

```bash
# On the GPU VM, terminal 1: start inference server
MODEL_PATH=/path/to/model.gguf \
N_GPU_LAYERS=-1 \
source inference/.venv/bin/activate && python inference/server.py

# On the GPU VM, terminal 2: start RA-TLS gateway
./target/release/sifir-server \
  --listen 0.0.0.0:7443 \
  --backend http://127.0.0.1:8080 \
  --amd --snp-product Genoa \
  --gpu-cc --gpu-attest-script ~/sifir/poc/inference/gpu_attest.py

# From your local machine:
cargo run -p sifir-client -- \
  --server $GPU_IP:7443 \
  --amd --gpu-cc \
  --max-tokens 128 \
  "Explain GPU confidential computing in one sentence."
```

Expected: verified attestation + LLM response from within the confidential VM.

### Clean up

```bash
az group delete --name sifir-poc-gpu --yes --no-wait
```

---

## Troubleshooting

### `/dev/snp-guest: No such file or directory`

The VM is not running inside an AMD SEV-SNP enclave, or the kernel module is not loaded.

```bash
sudo modprobe sev-guest
ls /dev/snp-guest
```

If the device still doesn't appear, the VM was provisioned without the `--security-type ConfidentialVM` flag. Reprovision with the correct flags.

### `KDS VCEK fetch failed: 404`

The chip_id or TCB version extracted from the report is wrong, or the product name is incorrect. Confirm the product name:

```bash
# Milan (EPYC 7xx3) — Azure DCasv5
./sifir-server --amd --snp-product Milan

# Genoa (EPYC 9xx4) — Azure NCC H100 v5
./sifir-server --amd --snp-product Genoa
```

### `DER signature parse error` / `P-384 key parse error`

The AMD cert chain uses RSA-4096 (Milan), but `amd_certs.rs` only handles ECDSA P-384 (Genoa). See DEVIATIONS.md D6. Use a Genoa VM, or add RSA support.

### `NVIDIA attestation failed: ...` from gpu_attest.py

Possible causes:

1. **CC mode is off:** Run `nvidia-smi --query-gpu=cc_mode --format=csv,noheader`. If `OFF`, the VM was not provisioned with CC mode. The NCC H100 v5 has CC mode on by default.

2. **SDK not installed:** `pip install nv-attestation-sdk>=1.4.0`

3. **Network not reaching NRAS:** The NRAS endpoint `https://nras.attestation.nvidia.com` must be reachable from the VM. Check outbound HTTPS is allowed in the Azure NSG.

### `measurement mismatch: expected=aaa...aaa, got=000...000`

The client was given the wrong expected measurement. Either:
- Use `--expected-measurement <zeros>` to skip the check during initial setup
- Get the correct measurement from the server startup log

### TLS handshake error on Phase 1 (mock)

Confirm server and client are both in the same mode (both mock, or both `--amd`). A mock server cert will be rejected by a client running `--amd` because the extension's `mode` field is `Mock` not `AmdSevSnp`.

---

## Expected output summary

| Phase | Server flags | Client flags | Expected result |
|-------|-------------|-------------|-----------------|
| 1 — mock | _(none)_ | _(none)_ | echo response, `attestation verified` |
| 1 — reject | _(none)_ | `--expected-measurement aa...aa` | TLS error, `measurement mismatch` |
| 2 — local inference | `--backend http://127.0.0.1:8080` | _(none)_ | real LLM response |
| 3 — AMD SNP | `--amd --snp-product Genoa` | `--amd` | real hardware attestation |
| 4 — GPU CC | `--amd --gpu-cc ...` | `--amd --gpu-cc` | CPU + GPU attestation, `model=H100, cc_mode=on` |
