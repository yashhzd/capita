# Results

Circuit benchmarks for the Capita Protocol prototype. Reproduce with:

```bash
cd capita/harness
npx tsx bench/bench.ts
```

## Toolchain

| | |
|---|---|
| Machine | Apple M4 Max, 14 cores, 36 GB RAM |
| OS | macOS 26.5.2 |
| `nargo` | 1.0.0-beta.22 |
| `@aztec/bb.js` | 5.1.0 |
| `@noir-lang/noir_js` | 1.0.0-beta.22 |
| Node.js | v22.14.0 |

## Circuit benchmarks

Median of 5 runs per circuit, one untimed warm-up excluded (absorbs one-time verification-key
computation and WASM/SRS initialization, a process cost rather than a per-transaction one).
Witnesses come from a real enroll/deposit/spend flow over live pool state, not synthesized
inputs, so the numbers reflect what a real transaction costs: Merkle membership from an opening,
the tally consume/update, and — for spend — the disclosure memo's in-circuit encryption. All
proofs verified.

| Circuit | ACIR opcodes | Witness gen | Prove | Verify | Proof size | Memo overhead |
|---|---:|---:|---:|---:|---:|---:|
| enrollment | 14 | 0.68 ms | 48.4 ms | 2.76 ms | 14,656 B | n/a |
| spend | 273 | 3.69 ms | 115.5 ms | 2.86 ms | 14,656 B | 192 B |

ACIR opcode count is `nargo info`'s constraint-system size for `main`, not the UltraHonk
backend's own gate count — the two measure different representations of the same circuit and
are not interchangeable. `bb gates` gives the backend gate count instead; the paper's evaluation
table cites that figure (322 gates for enrollment, 8,094 for spend), measured separately by
[`bench/spend-bench.ts`](harness/bench/spend-bench.ts).

Memo overhead is the disclosure memo's entire public footprint — `c1` (2 field elements) plus
`ct` (4 field elements), 6 × 32 bytes — over and above what a spend circuit with no privacy
mechanism would need to publish at all. Every accepted spend carries this whether the memo is a
dummy or a real report; that uniformity is a privacy property, not an implementation accident,
and [`bench/spend-bench.ts`](harness/bench/spend-bench.ts) measures it directly by proving both
positions and confirming the proof sizes and timings are indistinguishable.

## Below- vs above-threshold uniformity

This is the paper's headline empirical result and comes from a separate script,
[`bench/spend-bench.ts`](harness/bench/spend-bench.ts) (median of 10 runs), because the point of
that measurement is the *comparison* between two threshold positions on the identical circuit,
not a per-circuit summary:

| Circuit | Gates | Public inputs | Prove | Verify | Proof |
|---|---:|---:|---:|---:|---:|
| Enrollment | 322 | 3 | 47.4 ms | 2.73 ms | 14,656 B |
| Spend, below threshold | 8,094 | 16 | 110.1 ms | 2.75 ms | 14,656 B |
| Spend, above threshold | 8,094 | 16 | 110.2 ms | 2.74 ms | 14,656 B |

A spend that crosses the disclosure threshold and one that doesn't cost 110.2 ms vs. 110.1 ms
and emit byte-identical proofs and memos. Reproduce with `npx tsx bench/spend-bench.ts`.
