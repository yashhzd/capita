# Paper

`capita.tex` is the working draft of the Capita paper. Target is an ePrint preprint first
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

## Before submission

Open items tracked for the camera-ready:

- Replace the mocked credential layer, or cite published passport-circuit costs explicitly
  in the evaluation rather than only in threats to validity.
- Pull the verbatim quote from EDPB/EDPS Joint Opinion 02/2023 on decentralized identifier
  storage; currently paraphrased.
- Fill in author/venue details for the placeholder-titled entries in the bibliography
  (`popfoundations`, `earlt`, `aqqua`, `paxpay`, `wdap`, `dart`), which are cited by ePrint
  number and need full author lists.
- Re-check the prior-art sweep against CCS 2026 and AFT 2026 accepted lists, which were not
  public at the time of the original survey.
