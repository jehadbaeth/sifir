# Deviations from PLAN.md

This document records places where the implementation diverged from the plan, and why.

---

## D1 — CLI flag: `--amd` instead of `--mock true/false`

**Plan said:** `sifir-client --mock true` (boolean flag with value).

**Implemented as:** `sifir-client` (mock mode by default); pass `--amd` to switch to real AMD cert chain verification.

**Why:** clap 4 treats `bool` fields without a value argument as presence flags. Keeping `--mock` with a default of `true` would require `--mock=false` to disable it, which is confusing. Inverting to `--amd` (false by default) gives cleaner UX: add `--amd` when you have real hardware, omit it otherwise.

---

## D2 — `AttestationExtension` moved to `sifir-attest`

**Plan said:** `AttestationExtension` defined in `sifir-server/src/attest_ext.rs`.

**Implemented as:** `AttestationExtension` defined in `sifir-attest/src/attest_ext.rs`, re-exported from `sifir-server/src/attest_ext.rs`.

**Why:** Both the server (serialising the extension into the cert) and the client (deserialising it from the cert) need the same type. Putting it in the shared library avoids duplication and keeps the types identical.

---

## D3 — TLS pubkey binding uses SubjectPublicKeyInfo DER (two-step cert generation)

**Plan said:** "compute SHA-256(tls_pubkey_der)" — did not specify how to extract the pubkey DER before the cert exists.

**Implemented as:** Two-step cert generation: (1) generate a temporary self-signed cert to extract the SubjectPublicKeyInfo DER, (2) compute the hash, sign the attestation report, then generate the real cert with the attestation extension. The temporary cert is discarded.

**Why:** The attestation report must be signed before the cert is generated (the report is embedded in the cert's extension). To get the SPKI DER without a custom DER builder, parsing a temporary cert is the cleanest approach. Both server and client extract SPKI the same way (`x509_cert::Certificate → tbs_certificate.subject_public_key_info.to_der()`), ensuring consistency.

---

## D4 — `MEASUREMENT_SIZE` added to `sifir-attest` public API

**Plan said:** Not explicitly mentioned.

**Implemented as:** `sifir_attest::MEASUREMENT_SIZE = 48` exported from `lib.rs`.

**Why:** Both server and client need this constant (server for constructing the mock measurement; client for validating the `--expected-measurement` hex string length).
