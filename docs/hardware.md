# Hardware

## Target model: GLM-5.2

GLM-5.2 (released June 13, 2026, MIT license) is a Mixture-of-Experts model:
- **744B total parameters**, ~40B active per forward pass
- 1M token context window
- FP8 inference supported natively

Because MoE only activates ~40B parameters per forward pass, compute cost is closer to a 40B dense model. But all 744B parameters must reside in VRAM for routing.

## VRAM requirements

| Precision | Weight memory | KV cache (short ctx) | Minimum H100 80GB | Recommended |
|---|---|---|---|---|
| BF16 | ~1,488 GB | + 30–80 GB | 20 | 20 |
| FP8 | ~744 GB | + 30–80 GB | 10 | 10 |
| INT4 (AWQ) | ~372 GB | + 30–80 GB | 6 (tight) | 8 |

FP8 on 10× H100 is the recommended operating point: fits comfortably, maintains quality close to BF16, leaves headroom for KV cache at moderate context lengths.

At 1M context, KV cache can reach 100–160 GB depending on batch size. For long-context workloads, 12× H100 in FP8 is safer.

## Group size guidance

Group size is not a fixed number — it is derived from hardware capability and the group's usage patterns. There is no single correct answer; the guidance below helps a group choose hardware for their expected size, or understand how many members a given hardware configuration can comfortably support.

### How to think about it

The relevant question is: how many members can submit requests simultaneously without feeling like they are waiting on each other?

With continuous batching (vLLM's default mode), multiple requests are processed in parallel. The effective experience for each user depends on how many others are actively generating responses at the same moment.

```
comfortable simultaneous active users ≈ (T × W) / L

where:
  T = hardware throughput in tokens/sec
  W = acceptable wait time in seconds (group preference — suggested 10s)
  L = average response length in tokens (use-case dependent — suggested 500)
```

To get comfortable group size (not just simultaneous active users):

```
comfortable group size ≈ comfortable_simultaneous × (think_time / active_time)

where:
  think_time    = average seconds between a user's requests during an active session
  active_time   = W + L/T  (response latency — how long each request "occupies" a slot)
```

Think time varies widely: a developer iterating on code might send a new request every 20 seconds; someone reading a long research response might wait 3 minutes before the next one.

### Reference table (GLM-5.2, 10s acceptable wait, 500 tokens/response)

These are estimates. Real throughput for GLM-5.2 has not been benchmarked; the MoE architecture (40B active params) makes throughput hard to predict without measurement. Treat these as order-of-magnitude guidance, not guarantees.

| Hardware | Est. tokens/sec | Simultaneous active users | Comfortable group (30s think time) | Comfortable group (120s think time) |
|---|---|---|---|---|
| 6× H100 INT4 | 300–600 | 6–12 | 12–30 | 30–80 |
| 10× H100 FP8 | 500–1,500 | 10–30 | 20–75 | 50–200 |
| 16× H100 FP8 | 800–2,400 | 16–48 | 32–120 | 80–320 |
| 20× H100 BF16 | 400–1,000 | 8–20 | 16–50 | 40–130 |

The wide ranges reflect benchmark uncertainty. The higher end assumes favorable batching conditions; the lower end is conservative.

### What this means for a group

A group of 10–20 members sharing a 10× H100 FP8 cluster will generally have a good experience if they are not all working at the same time. A group concentrated in one timezone with similar working hours effectively has a narrower peak window — budget for the lower end of the range.

The governance parameters (see [`governance.md`](governance.md)) should be chosen to match the hardware-derived group size: N members, M-of-N threshold for routine decisions, (N-1)-of-N for membership admission.

### Scaling rule of thumb

Comfortable simultaneous users scales roughly linearly with hardware throughput. Doubling the number of H100s approximately doubles throughput (assuming tensor parallelism efficiency holds), which approximately doubles comfortable group capacity. Governance complexity also grows with N — very large groups (N > 20) should consider whether the coordination overhead is worth it.

---

## Why H100 and not consumer GPUs

Consumer cards (RTX 3090, 4090) lack NVLink. Without NVLink, tensor parallelism across multiple cards is bottlenecked by PCIe bandwidth (~16 GB/s per slot vs NVLink's ~600–900 GB/s aggregate). Distributed inference over the internet adds network latency on top. The result at 700B scale is 1 token/sec or less — not usable for interactive inference.

H100 SXM with NVLink is the minimum viable hardware for interactive inference at this model size.

## Cost estimates (mid-2026)

### GPU hardware only

| Config | Count | New (per unit) | New (total) | Used (per unit) | Used (total) |
|---|---|---|---|---|---|
| FP8 baseline | 10× H100 80GB SXM | $35k–40k | $350k–$400k | $15k–28k | $150k–$280k |
| FP8 long-context | 12× H100 80GB SXM | $35k–40k | $420k–$480k | $15k–28k | $180k–$336k |
| INT4 minimum | 6× H100 80GB SXM | $35k–40k | $210k–$240k | $15k–28k | $90k–$168k |

Used market pricing is volatile. Units sold below $15k often have unknown service history or come from secondary markets with degraded warranty coverage. Budget conservatively.

### Full system (add to GPU cost above)

| Component | Estimate |
|---|---|
| 2× server chassis (5× H100 each, NVLink bridges) | $20k–$40k |
| InfiniBand HDR networking between nodes | $5k–$15k |
| Storage (NVMe, OS, weights) | $5k–$10k |
| Colocation — rack, power (10–15 kW draw), 1G uplink | $800–$2,000/month |

### Total one-time cost (FP8 baseline, used GPUs)

| Item | Low | High |
|---|---|---|
| 10× H100 used | $150k | $280k |
| Servers + networking + storage | $30k | $65k |
| **Total** | **$180k** | **$345k** |

For a group of 10 members with equal contribution: **$18k–$34.5k per person**.

## Co-location rationale

The hardware must be co-located rather than distributed across members' homes for two reasons:

1. **Performance**: NVLink between GPUs requires physical proximity (same chassis or direct cable between chassis). Tensor parallelism over a wide-area network is not viable at this scale.

2. **Trust model**: Hosting at a colocation facility rather than a member's home removes one member from having privileged physical access. AMD SEV-SNP then protects against the facility operator. No single party — member or operator — can observe computation.

The colocation facility provides: power, cooling, physical security, and internet transit. Nothing else is needed from them, and nothing else should be granted to them.

## Power and cooling

A 10× H100 SXM system draws approximately:
- GPUs: 10 × 700W = 7,000W
- CPUs, memory, storage, networking: ~1,500W
- **Total: ~8,500–10,000W continuous**

This requires a colocation facility with:
- 20A 208V circuits (standard in most data centers)
- At minimum a 15 kW power allocation to leave headroom
- Adequate cooling for the rack (most colocation facilities can handle this as standard)
