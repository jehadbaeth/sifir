# Sifir

> *Sifir* — zero in Arabic and Turkish. Links to *cipher*. Zero trust, zero visibility, zero single point of control.

Sifir is a design for a **collectively owned, privately operated LLM inference cluster** where no single member — and no infrastructure provider — can see what anyone else asks, tamper with what's running, or gain disproportionate control.

A group of people jointly funds and hosts compute. They each get access proportional to what they contributed. Nobody has to trust anyone else.

---

## The core problem

Running a frontier-scale model (~700B parameters) requires hardware that no individual typically owns. The natural solution — pooling resources — breaks privacy: whoever holds the hardware can read your queries.

Sifir is a design for solving that contradiction.

## Key properties

- **Verifiable artifact** — every member can independently confirm what software is actually running, not just what they were told is running
- **Execution isolation** — the hardware operator (colo facility, fellow members) cannot observe computation even with physical access
- **Private communication** — each member's traffic is encrypted end-to-end to the trusted boundary; no intermediate party can read or replay it
- **Proportional, anonymous access** — usage rights are proportional to financial contribution; spending those rights reveals nothing about identity or query content
- **Distributed governance** — no single member or small subset can unilaterally change the deployment, issue access, or bypass the rules the group agreed on

## What Sifir is not

- A cloud service
- A blockchain project
- A replacement for commercial LLM APIs if you don't need the trust properties
- A finished implementation (this repository is a design and prototyping effort)

---

## Documents

- [`docs/architecture.md`](docs/architecture.md) — system layers, components, and diagrams
- [`docs/governance.md`](docs/governance.md) — setup ceremony, routine governance (FROST), membership admission (ring signature veto)
- [`docs/threat-model.md`](docs/threat-model.md) — who is distrusted, of what, and to what degree
- [`docs/token-economics.md`](docs/token-economics.md) — how access rights are issued, held, and spent
- [`docs/hardware.md`](docs/hardware.md) — hardware requirements, cost estimates, group size guidance

---

## Status

PoC phase. Architecture and threat model are complete. Implementation plan is at [`poc/PLAN.md`](poc/PLAN.md).

PoC phases:
- Phase 1: RA-TLS mock (local) — validates attestation verification mechanics
- Phase 2: Inference integration (local, RTX 3070) — validates full request path
- Phase 3: Real AMD SEV-SNP (Azure DCasv5) — validates CPU TEE attestation against genuine hardware
- Phase 4: GPU CC (Azure NCC H100 v5) — validates NVIDIA Confidential Computing attestation chain

Note: H100 does not encrypt NVLink traffic between GPUs. Full multi-GPU confidentiality requires Blackwell hardware. See `docs/threat-model.md` T1.
