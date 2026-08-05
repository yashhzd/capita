# Paper

`capita.tex` is the working draft of the Capita Protocol paper. Target is an ePrint preprint first
(for the priority timestamp), then a venue such as Financial Cryptography or AFT.

## Building

Any LaTeX engine works; the document uses only standard CTAN packages and a manual
`thebibliography`, so there is no `.bib` step and no custom class to install.

```bash
pdflatex capita.tex && pdflatex capita.tex   # twice, for cross-references
```

Or with [Tectonic](https://tectonic-typesetting.github.io), which fetches packages on demand
and resolves references in one pass:

```bash
tectonic capita.tex
```

## Where the numbers come from

Every figure in the evaluation section is measured, not estimated. Reproduce with:

```bash
cd ../capita/circuits/enrollment && nargo info    # ACIR opcode counts
cd ../capita/circuits/spend      && nargo info
bb gates -b target/spend.json                     # UltraHonk gate count

cd ../../harness && npx tsx bench/spend-bench.ts  # proving and verification timings
```

`bench/spend-bench.ts` builds witnesses from live pool state through the full
enroll, deposit, spend flow rather than synthesizing them, so the reported cost is the
cost of a real transaction. It measures both threshold positions, because the claim that
below- and above-threshold spends are indistinguishable is a privacy property and should
be checked rather than assumed.

Reported figures were taken on an Apple M4 Max (14 cores, 36 GB) under macOS 26.5.2, with
`nargo` 1.0.0-beta.22, Barretenberg 5.0.0-nightly.20260522, and Node.js 22.14.0.

## Citations

All 30 references were checked against primary sources (IACR ePrint, arXiv, publisher pages,
EUR-Lex, eCFR). The first 28 were verified on 2026-08-05; PayOff and ul-PCS were added and
verified on 2026-08-06. Titles, author lists, and venues match the record.

ul-PCS is cited as an ePrint report with no venue, because the ePrint page lists none. Do not
add one without checking the archive first.

This mattered: the first draft was assembled from terse research notes that recorded ePrint
numbers and one-line descriptions but not full citations, and seven titles had been inferred
from system acronyms rather than sourced. All seven were wrong. If you extend the bibliography,
verify each entry against the actual ePrint or arXiv page before it goes in. Do not reconstruct
a title from an acronym.

Two substantive corrections came out of the same pass and are worth not regressing:

- Article 35(8) of the digital euro proposal does not itself impose the holding limit. Article
  16(1) obliges PSPs to enforce it; 35(8) authorizes the ECB to establish the single access
  point that makes cross-provider enforcement possible. The paper now says so.
- Friolo et al. are not making a general argument against persistent payer state. They adopt a
  specific principle, that a payer should not retain secrets from one transaction to the next,
  and tie it to blackmail and coercion risk. Capita Protocol violates that principle directly, and §7
  now engages it on those terms rather than a softer paraphrase.

## Before submission

- **Mocked credential layer.** The prototype accepts a pre-verified `person_secret` instead of
  verifying passport chip signatures in-circuit. Disclosed in the threats-to-validity
  subsection. Either implement it or add published passport-circuit costs to the evaluation.
- **Proofs are sketches.** Section 5 gives game-based definitions with proof sketches. Adequate
  for a preprint; a top-tier venue will likely want full proofs, and the UC treatment is
  named as future work.
- **~~Fresh prior-art sweep.~~ Done 2026-08-06.** Second independent sweep, four days after the
  first, searching ePrint and arXiv directly rather than through result snippets and pulling
  full abstracts on every close candidate. Nothing was found combining personhood, cumulative
  amount thresholds, cross-account aggregation, unlinkable per-person state, and registrar-free
  operation. Two near misses were found and are now cited in Section 2: PayOff enforces an
  amount limit as an in-circuit inequality but scopes it to one wallet's secure element, and
  ul-PCS scopes its policies to single participants by construction. Also checked and ruled
  out: World AgentKit (per-human, but a request count, not an amount), RLN (stake-weighted
  counts, no personhood), Privacy Pools (source-of-funds legitimacy, not thresholds).
  Re-sweep once more immediately before submission to catch anything posted in the interim.
- **Optional:** Table 1 positions the work qualitatively. A quantitative comparison against
  PRCash, UTT, Platypus and PEReDi would strengthen the evaluation, but requires sourcing
  their reported numbers carefully rather than estimating.
