# Proving cost matrix

Cross-option benchmark of PK-build cost (`circuit_compute_vk`) over
the recursive-aggregation tier circuits. Reported as **peak RSS / wall-clock**.

## Bottom line

1. **`oracle_hash_type` and `zk` mode have ~no effect on PK-build cost** (< 2% across cells).
   - Implication: choice of on-chain verifier flavor is a free parameter at the proving cost level.
2. **`low_memory` does not help PK-build** and adds ~3% RAM + ~10% time.
   - Designed for the prove path, but even there our per-SU ownership circuit (~150 MiB)
     is too small to benefit. Useful only when polynomial workspace dominates RAM.
3. **`verify_rolluphonk_proof` does NOT help.** Per-call cost is *higher* than
   `verify_honk_proof_non_zk`, and barretenberg caps accumulated IPA claims at <4,
   so the flat-N variant fails for N ≥ 4.
4. **Flat aggregation scales linearly: ~1.4 GB and ~700 ms per inner verify call.**
   - N=1: 1.34 GB / 0.70s; N=2: 2.74 GB / 1.4s; N=4: 5.5 GB / 2.8s; N=8: 11 GB / 5.5s.
   - Mobile budget (iOS jetsam ≈ 3 GB / Android flagship ≈ 8-12 GB) caps native flat aggregation at N=2.
5. **Hierarchical (N=2 atom, `log2(target)` iterations) is mobile-feasible.**
   - Constant **2.74 GB / 1.4s per step**, regardless of target_N.
   - target_N=8 hierarchical: 4.3s total at 2.74 GB (vs flat N=8 at 5.5s and 11 GB).

---

Methodology:
- One process per cell (RSS reset via fresh process); macOS `getrusage`/`ru_maxrss` for peak.
- `barretenberg-rs 5.0.0-nightly.20260512`; `noir_rs` patched to match
  (see `vendor/noir_rs`); `bb_proof_verification v5.0.0-nightly.20260512`.
- Toolchain: `nargo 1.0.0-beta.20`, bb 5.0-nightly.
- `low_mem=on` enables barretenberg's file-backed polynomial storage
  (`BB_SLOW_LOW_MEMORY=1`), ~2x slower for ~50%+ less RAM.
- `zk=on` enables zero-knowledge variant (UltraHonkZK / ~12% bigger proofs).
- `ipa=on` enables IPA accumulation; required by `verify_rolluphonk_proof`
  and only valid with `oracle=poseidon2`. Barretenberg rejects keccak+ipa.

## Regular path (`verify_honk_proof_non_zk`)

### Oracle = keccak (matches our on-chain UltraHonkKeccak verifier)

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | 92 MiB / 68ms | 91 MiB / 73ms | 91 MiB / 61ms | 92 MiB / 72ms |
| **N=2** | 106 MiB / 76ms | 106 MiB / 91ms | 106 MiB / 88ms | 106 MiB / 88ms |
| **N=4** | 135 MiB / 109ms | 136 MiB / 118ms | 135 MiB / 107ms | 135 MiB / 120ms |
| **N=8** | 220 MiB / 161ms | 224 MiB / 168ms | 219 MiB / 152ms | 226 MiB / 162ms |

### Oracle = poseidon2 (would need a different on-chain verifier)

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | 91 MiB / 62ms | 91 MiB / 69ms | 92 MiB / 62ms | 92 MiB / 73ms |
| **N=2** | 106 MiB / 83ms | 106 MiB / 89ms | 106 MiB / 78ms | 105 MiB / 95ms |
| **N=4** | 135 MiB / 108ms | 137 MiB / 119ms | 135 MiB / 104ms | 136 MiB / 116ms |
| **N=8** | 221 MiB / 153ms | 223 MiB / 173ms | 219 MiB / 148ms | 223 MiB / 176ms |

## Rolluphonk path (`verify_rolluphonk_proof`, ipa=true, poseidon2)

Architectural note: `verify_rolluphonk_proof` is designed for
hierarchical rollup trees where each leaf verifies a small number of
inner proofs and **defers the IPA verification** as a public output.
Barretenberg enforces a per-circuit cap on accumulated IPA claims, so
the flat-N variant fails for N≥4 with `Too many nested IPA claims to
accumulate`.

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | — | — | — | — |
| **N=2** | — | — | — | — |
| **N=4** | — | — | — | — |
| **N=8** | — | — | — | — |

## Ownership-circuit prove (shows real `low_memory` effect)

PK-build (`circuit_compute_vk`) doesn't allocate the polynomial workspaces
that `BB_SLOW_LOW_MEMORY` targets, so the tables above show no `lm` effect.
This section runs an actual end-to-end `prove_ultra_honk_*` on the per-SU
ownership circuit, which IS affected by low_memory mode.

| oracle | low_mem | prove time | peak RSS |
|---|---|---|---|
| keccak | off | 0.15s | 109 MiB |
| keccak | on | 0.18s | 110 MiB |
| poseidon2 | off | 0.17s | 103 MiB |
| poseidon2 | on | 0.20s | 112 MiB |

## Hierarchical / constant-memory analysis

**Key insight**: aggregation cost in a flat recursive circuit scales
**linearly in N** (each `verify_honk_proof_non_zk` call adds ~1.3 GB to
PK-build memory). A hierarchical / binary-tree approach pays
**constant memory per step** using the smallest tier (N=2) as the
aggregation atom, iterated `log2(target_N)` times.

Per-step cost = `regular/N=2/.../zk=off/lm=off` cell of the table above.

Total wall-clock for aggregating `target_N` SUs hierarchically:
  `log2(target_N) * step_time`. Peak RAM stays at the N=2 cell value.

| target_N | levels (log2) | total wall-clock (using zk=off lm=off step) |
|---|---|---|

Reference N=2 step: **106 MiB / 0.08s** (peak RAM is the same regardless of `target_N`).

| target_N | levels | wall-clock |
|---|---|---|
| 2 | 1 | 0.08s |
| 4 | 2 | 0.15s |
| 8 | 3 | 0.23s |
| 16 | 4 | 0.30s |
| 32 | 5 | 0.38s |
| 64 | 6 | 0.46s |

---

**Raw results**: `/tmp/outbe-cost-matrix.jsonl`