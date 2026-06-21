#!/usr/bin/env python3
"""
Sifir GPU attestation sidecar — Phase 4 (Azure NCC H100 v5).

Fetches NVIDIA GPU CC attestation evidence via the NVIDIA attestation SDK
and writes a JSON result to stdout. The nonce binds the GPU attestation to
the specific TLS session (it must equal hex(SHA-256(TLS_SPKI_DER))).

Usage:
    python gpu_attest.py --nonce <64-char-hex>

Output (stdout, JSON):
    {"jwt": "<nras-jwt>", "nonce": "<hex>"}

Exit codes:
    0  success
    1  SDK/attestation error (details on stderr)
    2  bad arguments

Requires:
    pip install nv-attestation-sdk>=1.4.0

On Azure NCC H100 v5, the GPU must be in CC mode (verify with:
    nvidia-smi --query-gpu=cc_mode --format=csv,noheader
which should return "ON").
"""
import argparse
import json
import sys


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch NVIDIA GPU CC attestation JWT")
    p.add_argument(
        "--nonce",
        required=True,
        help="64-character hex nonce = hex(SHA-256(TLS_SPKI_DER))",
    )
    return p.parse_args()


def validate_nonce(nonce: str) -> None:
    if len(nonce) != 64:
        print(
            f"ERROR: nonce must be 64 hex chars (got {len(nonce)})", file=sys.stderr
        )
        sys.exit(2)
    try:
        bytes.fromhex(nonce)
    except ValueError:
        print("ERROR: nonce must be valid hex", file=sys.stderr)
        sys.exit(2)


def fetch_gpu_jwt(nonce: str) -> str:
    """
    Fetch a GPU attestation JWT from NRAS using the NVIDIA attestation SDK.

    The SDK must be installed: pip install nv-attestation-sdk>=1.4.0
    NRAS endpoint: https://nras.attestation.nvidia.com
    OCSP endpoint: https://ocsp.ndis.nvidia.com
    """
    try:
        from nv_attestation_sdk.attestation import Attestation, Devices, Environment
    except ImportError:
        print(
            "ERROR: nv-attestation-sdk not installed.\n"
            "Install with: pip install nv-attestation-sdk>=1.4.0",
            file=sys.stderr,
        )
        sys.exit(1)

    nras_url = "https://nras.attestation.nvidia.com"
    ocsp_url = "https://ocsp.ndis.nvidia.com"

    try:
        client = Attestation()
        # GPU device, production NRAS, with OCSP cert revocation checking.
        client.add_verifier(
            Devices.GPU,
            Environment.REMOTE,
            nras_url,
            ocsp_url,
        )
        client.set_nonce(nonce)

        # Returns a list of JWT tokens (one per verifier).
        tokens = client.attest()
        if not tokens:
            print("ERROR: attestation returned no tokens", file=sys.stderr)
            sys.exit(1)

        return tokens[0]

    except Exception as exc:
        print(f"ERROR: NVIDIA attestation failed: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    args = parse_args()
    validate_nonce(args.nonce)

    jwt = fetch_gpu_jwt(args.nonce)

    result = {"jwt": jwt, "nonce": args.nonce}
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
