# Threat Model

## What we are protecting

- **Query content and responses**: what each member asks and receives
- **Usage patterns**: how much any member uses, when, and inferred from that, what they might be doing
- **Identity linkage**: connecting a query or usage pattern to a real person
- **Deployment integrity**: whether what is running is actually what the group approved

## Parties and trust assumptions

| Party | Trusted for | Not trusted for |
|---|---|---|
| **AMD** | Correct implementation of SEV-SNP hardware and attestation | Supply chain, undisclosed firmware backdoors |
| **Colocation facility** | Physical access (power, cooling, network transit) | Observing computation, intercepting traffic, modifying hardware |
| **Group members** | Participating in governance (signing with their key) | Observing other members' queries, unilateral deployment changes |
| **Internet transit** | Routing packets | Confidentiality or integrity of any individual packet |
| **Model publisher (Zhipu AI)** | Publishing the weights with a stable hash | Model behavior, backdoors encoded in weights |

No party is fully trusted. Every trust assumption is bounded and explicit.

## Threat scenarios

### T1 — Colocation facility operator reads query traffic

**Attack**: facility staff intercept traffic at the network boundary, read server memory, or read GPU VRAM during inference.

**Mitigation — CPU path**: AMD SEV-SNP encrypts VM memory with a key the hypervisor and host OS cannot access. RA-TLS terminates TLS inside the TEE; the facility cannot decrypt traffic at the network boundary. Physical access to the DIMM slots does not yield readable memory.

**Mitigation — GPU path**: NVIDIA H100 Confidential Computing (CC) mode encrypts HBM VRAM with a key generated inside the GPU security processor. PCIe traffic between CPU and GPU is encrypted end-to-end. The GPU's CC state is attested alongside the CPU's SEV-SNP attestation — clients verify both before sending data.

**Residual risk (H100 generation)**: NVLink traffic between GPUs in a multi-GPU SXM system is not encrypted in H100 CC mode. The NVLink firewall prevents peer GPUs from reading each other's compute-protected memory, but a physical bus tap on the NVLink interconnect would expose inter-GPU activations in transit. This affects the multi-GPU tensor-parallel inference required by GLM-5.2 (10× H100). A physical NVLink bus tap requires specialized hardware not available to a standard colo facility; this is accepted as a residual risk for H100-based deployments. Full NVLink encryption requires Blackwell (B200/GB200) hardware. Single-GPU workloads (models fitting within 94GB) have no NVLink exposure.

---

### T2 — Member A reads member B's queries

**Attack**: a member with administrative access to the cluster observes what other members ask.

**Mitigation**: no member has administrative access to the running VM. The VM is governed by threshold signature — no individual can redeploy or modify it unilaterally. Queries are routed through RA-TLS directly to the TEE; no member sits on that path.

**Residual risk**: a member who compromised M-of-N other members' signing keys could deploy a modified version that logs queries.

---

### T3 — Deployment is silently replaced with a logging version

**Attack**: an adversary (insider, compromised member, facility) replaces the running software with a version that logs all queries.

**Mitigation**: any deployment requires M-of-N governance signatures (FROST threshold). The deployed software measurement is included in the SEV-SNP attestation report. Every client verifies the attestation before sending data. A substituted deployment will produce a different measurement, and any client running verification will detect it and refuse to connect.

**Residual risk**: M-of-N members collude to approve a malicious deployment. The group's social threat model determines whether this is acceptable.

---

### T4 — Usage patterns reveal identity

**Attack**: even without reading query content, tracking which member spent tokens at what time reveals usage patterns.

**Mitigation**: blind token scheme (PrivacyPass protocol). Tokens are issued in a way that the issuer cannot link a token to the member who received it. When spent, the TEE verifies validity but has no record of issuance. Spending does not reveal identity to any party inside or outside the system.

**Residual risk**: timing correlation — if a member is the only one sending requests during a window, the facility can observe that a request was made even if they cannot read it. This is a metadata leakage that blind tokens do not solve.

---

### T5 — Member over-consumes the shared resource

**Attack**: a member uses more than their proportional share.

**Mitigation**: token balance is enforced inside the TEE. Members receive tokens proportional to their financial contribution. The TEE deducts tokens per output token generated. Token balances persist in TEE-sealed storage that survives reboots but is tied to the software measurement — a redeployment resets the state unless the new deployment migrates it, which requires a governance vote.

**Residual risk**: token issuance policy changes require governance votes, which can be slow. Abuse before governance catches it is bounded by token balance, not time.

---

### T6 — Hardware is secretly replaced mid-operation

**Attack**: a facility employee replaces an H100 or swaps a server with a modified one containing surveillance hardware.

**Mitigation**: AMD SEV-SNP attestation includes hardware identity. A replacement machine will not produce the same attestation report. Clients will refuse to connect after a hardware swap until the group explicitly re-approves the new hardware measurement via governance.

**Residual risk**: the group must run attestation verification continuously (or at least at connection time) to catch this. A monitoring system that alerts on measurement changes is needed.

---

## What Sifir does not protect against

- **The model itself**: GLM-5.2 weights are a black box. The model may exhibit biases, behavioral patterns, or fine-tuned behaviors that the group did not consent to. Verifying weights by hash confirms identity, not behavior.
- **M-of-N collusion**: if enough members collude, they can approve any deployment. The threshold M should be chosen so that this requires coordinating a number of people the group considers implausible.
- **Client device compromise**: if a member's local machine is compromised, their queries are exposed before they reach the RA-TLS layer.
- **Traffic analysis at scale**: a nation-state observer with access to internet backbone routing can correlate encrypted traffic timing and volume with external behavior even without reading content.
- **Physical coercion**: a member under physical duress can be forced to sign a governance action with their key.

## Threat model inputs still needed from the group

Before the architecture can be finalized, the group should decide:

1. Who is the realistic adversary — a nosy facility operator, a disgruntled member, a corporate competitor, a state actor?
2. What M-of-N threshold is appropriate? Higher M means more resistance to collusion but more coordination overhead for legitimate changes.
3. Is approximate fairness acceptable (token quotas) or does exact fairness matter?
4. How are signing keys held? Hardware security keys? Multi-device? Geographic distribution?
