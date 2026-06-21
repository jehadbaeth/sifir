# Governance

Governance in Sifir has three distinct phases that use different cryptographic tools, because the security requirements of each phase are different.

Governance runs **on the machine itself, inside the TEE** — not on any external blockchain or DAO. An on-chain DAO would make membership rosters, voting history, and governance actions permanently public on a global ledger, which directly contradicts the privacy model. All governance logic is part of the verifiable NixOS artifact: any member can read the rules, rebuild the derivation, and confirm what is actually enforced.

---

## Where governance state lives

Governance state (membership roster, token issuance policy, M-of-N threshold, governance log) lives in two places:

1. **Inside the TEE** — sealed storage encrypted to the SEV-SNP measurement. This is the authoritative copy. The TEE enforces governance rules.
2. **Distributed to members** — each member holds a copy of the governance log. This is the audit trail.

The governance log is an append-only chain of signed events:

```
event = {
  sequence:   integer (monotonically increasing)
  action:     proposal hash + action type
  signature:  FROST group signature (proves M-of-N approved)
  prev_hash:  hash of the previous event
  timestamp:  wall-clock time (approximate — not a consensus clock)
}
```

Any member can verify the log against the group public key. If the TEE's sealed state and a member's local log copy ever diverge, the signed log is the audit record for dispute resolution. A TEE that cannot produce a log consistent with member copies has been tampered with — clients will detect this via attestation verification.

---

## How voting works in practice

Voting is asynchronous and happens out of band.

```mermaid
sequenceDiagram
    participant P as Proposer (any member)
    participant CH as Out-of-band channel\n(Signal, Matrix, email)
    participant Mx as Other members (local machines)
    participant TEE as Governance endpoint (TEE)

    P->>CH: Broadcast proposal\n(human-readable description + SHA-256 hash of artifact)
    CH->>Mx: Members review proposal offline
    Mx->>Mx: Run local FROST signing tool\nwith own key share
    Mx->>TEE: Submit partial signature
    Note over TEE: Collects partial signatures
    TEE->>TEE: Once M threshold reached:\naggregate into group signature
    TEE->>TEE: Execute governance action\nAppend to governance log
    TEE->>CH: Broadcast signed log entry\n(members update local copies)
```

No member needs to be online simultaneously. Partial signatures accumulate until the threshold is met. The TEE is the aggregator and enforcer — it does not need to trust the channel used to coordinate the vote.

---

## Phase 1 — Setup ceremony

Before the cluster operates, the group needs a shared governance keypair that no single member holds.

**Preferred: FROST Distributed Key Generation**
Members run a two-round protocol. No single party generates the full key — each member derives their own key share locally from public commitments. The full private key never exists anywhere. The group's public key is the output.

**Simpler alternative: Shamir ceremony (trusted dealer)**
One member generates the keypair, splits the private key into N Shamir shares, distributes them, and destroys the original. Requires trusting the dealer during the ceremony window. Appropriate for a group that already has a trusted member willing to act as dealer and wants to minimize implementation complexity at the start.

```mermaid
sequenceDiagram
    participant M1 as Member 1
    participant M2 as Member 2
    participant Mn as Member N

    Note over M1,Mn: FROST DKG (preferred)
    M1->>M1: Generate commitment + share polynomial
    M2->>M2: Generate commitment + share polynomial
    Mn->>Mn: Generate commitment + share polynomial
    M1-->>M2: Secret share for M2
    M1-->>Mn: Secret share for Mn
    M2-->>M1: Secret share for M1
    Note over M1,Mn: Each member aggregates their shares.\nGroup public key is derived.\nNo one holds the private key.

    Note over M1,Mn: Shamir ceremony (simpler, trusted dealer)
    M1->>M1: Generate keypair
    M1->>M2: Shamir share 2
    M1->>Mn: Shamir share N
    M1->>M1: Destroy private key
    Note over M1: Dealer knew the full key during ceremony.
```

From the ceremony forward, the full private key never exists. All governance actions use FROST partial signatures.

---

## Phase 2 — Routine governance (FROST threshold)

Applies to: software/model updates, token policy changes, hardware expansion or replacement, changes to the M-of-N threshold.

Threshold: **ceil(2N/3)** — two-thirds supermajority. Groups may set a different value at setup.

```mermaid
flowchart TD
    PROP["Proposal broadcast\nhash(artifact or policy change)"]
    COLLECT["Members submit FROST partial signatures\n(asynchronous, via governance endpoint)"]
    AGGED{"Threshold\nreached?"}
    EXECUTE["TEE executes action\nAppends to governance log\nDistributes log entry to members"]
    WAIT["Continue collecting signatures\n(proposal expires after T days if threshold not met)"]

    PROP --> COLLECT --> AGGED
    AGGED -->|yes| EXECUTE
    AGGED -->|no| WAIT --> COLLECT
```

Partial signatures are attributable — each member's vote is visible to other members. This is appropriate for operational decisions and creates accountability.

---

## Phase 3 — Membership admission (FROST supermajority)

Adding a member is the highest-stakes governance action. It permanently expands the group, changes the M-of-N threshold, and requires a new FROST key share to be issued.

Threshold: **ceil(4N/5)** — 80% supermajority. Higher than routine governance because the decision is irreversible in the short term (removing a member requires another supermajority vote and a full group re-key).

```mermaid
flowchart TD
    APP["New member application\nbroadcast to all current members\n(includes applicant public key + contribution proof)"]
    REVIEW["Review window: 7 days\nMembers deliberate out of band"]
    VOTE["Members submit FROST partial approvals\nvia governance endpoint"]
    CHECK{"80% threshold\nmet within window?"}
    ISSUE["TEE issues new key share\nMembership roster updated\nM-of-N thresholds recalculated\nGovernance log updated"]
    DENY["Application denied\nNo reason required"]

    APP --> REVIEW --> VOTE --> CHECK
    CHECK -->|yes| ISSUE
    CHECK -->|no| DENY
```

The applicant's public key is included in the proposal hash that members sign. Approving a proposal implicitly approves that specific key — a substituted key would produce a different proposal hash and require a new vote.

**On anonymity**: votes are attributable (visible to other members). For a group of pseudonymous strangers transacting via crypto, this is acceptable — social retaliation risk is low when members do not know each other offline. If a group's threat model requires anonymous voting, threshold ring signatures are the right tool, but they add significant cryptographic complexity and are deferred from the PoC.

---

## Decommissioning

Decommissioning is the one governance action that cannot be fully handled cryptographically, because it involves physical hardware and real money.

**TEE-side (cryptography handles this)**:
1. M-of-N members sign a decommission proposal
2. TEE verifies, then executes:
   - Settles remaining token balances (refunds proportional to unused tokens and contribution share)
   - Invalidates all member key shares
   - Wipes sealed governance state
   - Closes the governance and inference endpoints
3. Final governance log entry is distributed to all members

**Hardware-side (legal agreement handles this)**:
The resale or disposal of physical hardware cannot be enforced cryptographically — it requires either a legal agreement made at group setup time, or a trusted third party to hold proceeds. Recommended: a written agreement at setup defining how hardware value is split on dissolution, signed by all members in their real identities (or pseudonymous identities they commit to for legal purposes).

```mermaid
flowchart LR
    PROP["Decommission proposal\nsigned by M-of-N members"]
    TEE_EXEC["TEE executes:\n1. Settle token balances\n2. Invalidate key shares\n3. Wipe sealed state\n4. Close endpoints\n5. Final log entry"]
    HW["Hardware disposal\nper setup agreement\n(outside cryptographic scope)"]

    PROP --> TEE_EXEC --> HW
```

---

## Governance parameters

| Parameter | What it controls | Suggested default |
|---|---|---|
| N | Total members | Derived from hardware capacity — see hardware.md |
| M_routine | Threshold for deployments, policy changes | ceil(2N/3) |
| M_admit | Threshold for membership admission | ceil(4N/5) |
| M_decommission | Threshold to shut down the cluster | ceil(4N/5) |
| Review window | Time a proposal stays open | 7 days |
| Proposal expiry | Time before an incomplete vote is dropped | 14 days |

Changing any of these parameters is itself a routine governance action (requires M_routine signatures).

---

## Key lifecycle

| Event | Mechanism |
|---|---|
| Initial key generation | FROST DKG or Shamir ceremony |
| Routine signing | FROST partial signatures (M_routine-of-N) |
| New member key issuance | TEE issues share after M_admit approval |
| Member removal | Supermajority vote → full group re-key via new FROST DKG round |
| Lost key recovery | Member proves identity to group (out of band) → M_routine approve new share |
| Decommission | M_decommission sign → TEE wipes all keys and state |

---

## Open questions

- **Proposal communication channel**: members need a way to share proposals and coordinate out of band. The system does not prescribe one — but the channel is outside the trust boundary. A compromised channel cannot forge signatures, but it could suppress proposals. Groups should use a channel with some redundancy (multiple paths).
- **Clock skew**: the governance log uses wall-clock timestamps. These are approximate and not consensus-verified. Good enough for audit purposes; not good enough for anything that needs precise ordering.
- **Hardware replacement ceremony**: replacing a failed GPU changes nothing about governance. Replacing an entire server changes the SEV-SNP measurement — clients will detect the change via attestation. A hardware replacement requires a routine governance vote to approve the new measurement before the cluster is trusted again.
