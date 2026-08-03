# Prior-art notes (condensed from three adversarial sweeps, 2026-08-01/02)

Verdict that drives the paper: per-person cumulative AMOUNT limits via self-sovereign personhood in permissionless shielded payments = unclaimed. Every neighboring cell occupied. This file is the citable skeleton for the Related Work section.

## The three-layer map (Related Work structure)

### Layer 1 — identity (self-sovereign personhood → sybil-resistant key): exists, no payments-limits use
- zk-creds — anonymous credentials from ICAO passports, no issuer coordination (Rosenberg/White/Garman/Miers, IEEE S&P 2023, ePrint 2022/878)
- SyRA — sybil-resilient anonymous signatures, threshold-VRF issuance, name-drops AML (Crites/Kiayias/Kohlweiss/Sarencheh, ePrint 2024/379, CCS 2025). NB: pseudonym linkable within a context — the supercookie failure we must beat
- Ring VRFs — permissionless per-person rationing, counts only (Burdges et al., ePrint 2023/002)
- PoP formalization — ideal functionalities, no payments (Choudhuri/Garg et al., ePrint 2026/333)
- ZK-AMS — PHC → one-per-person anonymous Soul Accounts, no spending accounting (arXiv 2602.16130)
- Cerezo Sánchez — ePassport zk-PoI on permissionless chains, 2019 (ePrint 2019/546)
- Ecosystem: zkPassport (Noir, scoped uniqueIdentifier), Self, Anon Aadhaar, World ID (Orb; WID4 threshold-OPRF one-time nullifiers — count semantics)

### Layer 2 — accounting (cumulative amounts across unlinkable sessions): exists key-bound, never person-bound
- BBA+ (Hartung et al., CCS 2017); Updatable Anonymous Credentials (Blömer/Bobolz et al., CCS 2019, ePrint 2019/169); Black-Box Wallets (PoPETs 2020); P4TC (ePrint 2018/1106) — unlinkable value accumulation, double-spend detection, but token/key-bound: one human opens many
- Unirep + anon-transfer (github.com/vivianjeng/anon-transfer) — working code, amounts across rotating epoch keys; attester trust, no personhood, no limits
- Count-based cousins: CHL e-tokens (CCS 2006), k-TAA, ACT (Asiacrypt 2023), ARC (IETF draft), EARLT (Asiacrypt 2025, ePrint 2025/1030 — identity revealed above N shows: our enforcement shape, count domain), SMA2RT (ePrint 2026/518)

### Layer 3 — enforcement (limits + disclosure in payment systems): exists per-account or registrar-bound
- Registrar family (per-user limits via registration DB): UTT (ePrint 2022/452), PRCash (2018/412), PEReDi (2022/974), Platypus (2021/1443), GGM16 (2016/061), Xue et al. (TDSC 2022), Gross et al. CBDC, PayOff (arXiv 2408.06956), Paxpay (2025/098, AFT 2025 — lifetime cap + regulator key), AQQUA (2024/1181, audit-time), WDAP (2023/1138), DART (2025/239), PARScoin (2023/1908)
- CAP/CAPE (Espresso, github.com/EspressoSystems/cap) — in-circuit `tpk=⊥ ∨ b_threshold=1 ∨ memo=Enc_tpk(record)`: per-TX threshold viewing, deployed 2022. Our uniform-memo design extends this to cumulative triggers
- Surveys: Nardelli et al. (arXiv 2505.21008; "Anonymity Budget"/"Operating Limits" taxonomy; silent on multi-account evasion and personhood — quotable gap), Chatzigiannis et al. SoK (ePrint 2021/239)
- Friolo et al. (arXiv 2409.01958) — argues NO persistent payer state (coercion surface); the objection our unlinkability property answers

## Industry near-misses (cite-and-distinguish)
- World AgentKit + x402 (Mar 2026) — per-human limits across AI agents, COUNT/usage only, custodial stack
- human.tech Clean SDK → Aztec (Jul 21, 2026) — personhood + shielded pool, binary gating, no amounts
- zkBob — epoch-reset tiered deposit caps, anti-splitting rationale in docs (closest conceptual grey-lit for structuring motivation)
- 0xbow Privacy Pools — deposit caps tried and REMOVED; ASP screening paradigm
- Fluxe (ethresear.ch/t/22714) — daily/monthly limits in compliance state machine, callback-enforced, not in-circuit
- Aleo ARC-0100 — $10k/day de minimis for bridge OPERATORS, off-chain policy
- GNU Taler — exchange-side aggregation ("renders structuring inherently ineffective"), account-anchored
- Ian Miers "Stateful ZK Identity" / zk-promises (ZK Podcast 389, Feb 2026) — right primitive family, social apps only

## Legal / institutional anchors (verified live)
- 31 CFR 1010.313(b) — same-person cross-account aggregation per business day (ecfr.gov; FFIEC manual; FinCEN admin ruling on aggregation)
- FinCEN NPRM 85 FR 83840 (Dec 23, 2020) — proposed CTR-style 24h aggregation for CVC; died
- EU digital euro proposal Art. 35(8) + ECB Single Access Point (central identifier registry; ECB degov240325/degov240411 technical notes)
- EDPB/EDPS Joint Opinion 02/2023 — SAP proportionality challenged; "decentralized storage of identifiers feasible" (pull verbatim quote from opinion PDF before submission)
- BIS Aurum 2.0 — tiered-KYC wallet limits, no personhood/dedup
- Nobody in crypto literature cites 1010.313 as a design requirement (clean negative, claimable framing)

## Named scoop risks
Sarencheh (Edinburgh thesis 2025, SyRA/PEReDi line); Garg group (2026/333 foundations); Lysyanskaya rate-limited-token line (counts→amounts step); World/human.tech industry track (composition shipped minus amounts, Jul 2026)

## Residual coverage gaps from sweeps
X/Twitter under-indexed (native search not run); one unresolved ETHGlobal project ("agent card bound to World humanId with spending caps" — delegation budgeting per snippet, name unknown); CCS 2026/AFT 2026 accepted lists not yet public at sweep time; FC26 "Compliance as a Trust Metric" judged by title only. Re-check all four before ePrint submission.
