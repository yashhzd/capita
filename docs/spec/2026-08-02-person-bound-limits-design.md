# Capita: Person-Bound Spending Limits for Shielded Payments Without a Registry

**Date:** 2026-08-02
**Status:** Draft for author review
**Deliverable:** Research paper (ePrint preprint first, then FC/AFT submission) + PoC implementation as its evaluation section

## 1. Thesis

Regulatory volume limits can be enforced per unique human — across any number of unlinkable accounts, with no registration authority and no central registry — in a permissionless shielded payment system, without the per-person state becoming a linking tag.

## 2. Motivation (the paper's opening argument)

Two legal regimes already mandate per-person aggregation that no private payment system can perform:

- **US:** 31 CFR 1010.313(b) requires banks to aggregate same-person currency transactions across accounts per business day for CTR filing. FinCEN's Dec 2020 NPRM (85 FR 83840) proposed porting exactly this to crypto.
- **EU:** the digital euro proposal (Art. 35(8)) mandates per-person holding limits across all payment providers. The ECB's implementation is a central registry of user identifiers (the "Single Access Point"). The EDPB/EDPS Joint Opinion 02/2023 objected and stated decentralized storage of these identifiers is technically feasible — no such design exists.

Every academic per-user-limit system (UTT, PRCash, PEReDi, Platypus) achieves person-binding only via a registration authority holding a user database. Every permissionless system (Zcash, Railgun, Privacy Pools, Aztec) binds limits — where it has any — to accounts, which are free to create. The empty cell: person-bound limits, permissionless, no registry.

## 3. Goals

1. **Person-binding:** opening new accounts/wallets does not reset or multiply a person's limit.
2. **Limit soundness:** a person cannot move more than threshold T per period across all their accounts without producing a valid disclosure to the auditor.
3. **Unlinkability (no supercookie):** transactions are unlinkable to each other and to the person, for all observers including the pool operator; the auditor learns only above-threshold disclosure records.
4. **No registrar:** no party ever holds a database of enrolled identities; enrollment is self-sovereign from a government-signed credential.
5. **Buildable PoC in weeks** by one strong engineer using existing tooling.

## 4. Non-goals / explicit non-claims

- Novelty of threshold-triggered disclosure per se (CAP/CAPE, PRCash, GGM16 — cited and extended).
- Novelty of the passport-credential layer (zk-creds, zkPassport — consumed, not rebuilt).
- Dual/multiple citizenship: a person with two passports gets two limit slots (2×T, bounded; acknowledged, unsolved by any personhood system).
- Willing human mules ("allowance markets"): a person routing spends through another consenting human's allowance is conspiracy, handled by law, not cryptography. The system still bounds total flow ≤ q·T for q participating humans — stated as a property, not a defect.
- Stolen/coerced passports; state-level credential forgery (trust root = government signing keys, as at every border).
- Receive-side aggregation (v1 tracks spend-side; receive-side discussed as extension).
- Full UC treatment (game-based definitions + proof sketches; venue-appropriate).

## 5. System model and roles

- **Person:** holds an ICAO e-passport (NFC chip, government-signed data). Derives all secrets from it. May use any number of wallets/accounts.
- **Pool:** a permissionless shielded UTXO pool (commitment Merkle tree + nullifier sets), maintained by a contract or any consensus layer. Holds no identity data.
- **Auditor:** holds decryption key APK for disclosure memos. Honest-but-curious; learns only disclosure records (pseudonymous). Single key in v1; threshold committee cited as extension (DART, UTT precedent).
- **Credential layer:** zkPassport-style circuits proving passport validity/signature under published government keys. Consumed via a defined interface; PoC may mock it (see §9).

## 6. Architecture decision

**Chosen: pool-native shielded tally notes ("the compliance state is itself a shielded note").**

The person's running total lives as a special note — a *tally note* — in the same commitment tree as payment notes. Every spend consumes the person's current tally note and creates an updated one, unlinkably, exactly as the pool's money notes already work. Person-binding comes from a one-time enrollment that emits a per-person nullifier, making second tally chains impossible.

**Rejected alternatives:**

- **Unirep-style attester architecture:** per-person state in an attester-managed tree with rotating epoch keys. Rejected: introduces attester trust and liveness; its sybil-resistance requires personhood-gating signup anyway; strictly more moving parts than reusing the pool's own tree.
- **BBA+/UACS rerandomizable credential:** user carries an unlinkable updatable token encoding the total. Rejected: updates require an issuer signature — a registrar in disguise; escaping that needs a threshold-issuer committee, heavy for v1 and weaker than pool-native for the "no registrar" claim.

## 7. Construction specification

### 7.1 Identity derivation

- `person_secret = H(passport_data_full)` — MRZ + chip data groups + signature material; treated as a secret known only to the holder (standard zkPassport threat model).
- `person_id = H(person_secret, APP_SCOPE)` — scoped to this system; identifiers in other apps are unlinkable to ours.
- v1 binds to the *document* (renewal = new slot, rate-limited by government issuance). Personal-data binding (name+DOB+nationality) trades renewal-persistence against real collision risk; discussed, not chosen.

### 7.2 Notes and commitments

- Payment note: `{value v, owner_pk, randomness r}`, commitment `C = Poseidon(v, owner_pk, r)`.
- Tally note: `{person_id, subtotal s, day d, randomness r}`, commitment `C_t = Poseidon(person_id, s, d, r)`.
- Both note types live in one Merkle tree. Nullifiers: `N = PRF(person_secret or owner_sk, C)`. Standard sets reject reuse.

### 7.3 Enrollment (one-time per person)

Circuit proves: valid passport credential (via credential-layer interface) → `person_id` correctly derived → outputs enrollment nullifier `E = H(person_id, "enroll")` and genesis tally commitment `C_t(person_id, s=0, d=today)`.
Contract/harness rejects duplicate `E`. On-chain trace: one opaque `E` + one commitment. Metadata leak: the *fact and time* of one enrollment event (acknowledged; batching/delays mitigate).

### 7.4 Spend circuit (the core)

Public inputs: Merkle root, current day `d_now` (enforced by contract/harness), payment nullifiers, new commitments, tally nullifier, new tally commitment, memo ciphertext, auditor key APK, threshold T.
Proves, in one proof:

1. **Payment validity** (standard): input notes exist in tree, owned by prover, value conservation, output commitments well-formed.
2. **Tally consume:** the prover supplies `person_secret` as witness; the circuit re-derives `person_id` from it (§7.1), proves a tally note carrying exactly that `person_id` exists in the tree, and reveals its nullifier `PRF(person_secret, C_t)`. (Old tally reuse = double-spend, rejected by nullifier set. Skipping the tally is impossible: the circuit requires it for every spend. Forging a tally for a different person requires their `person_secret`, i.e., their passport data.)
3. **Tally update:** if `d_now > d_old`: `s_new = v_spend` (business-day reset, matching 31 CFR 1010.313 semantics); else `s_new = s_old + v_spend`. New tally commitment binds `(person_id, s_new, d_now)`. Range checks throughout.
4. **Uniform disclosure memo:** `memo = Enc_APK(m)` with in-circuit proof of correct encryption, where `m = (person_id, s_new, d_now)` if `s_new > T`, else `m = ⊥` (fixed-format dummy). **Every** spend carries an identically-shaped memo — on-chain observers cannot tell threshold crossings from ordinary spends; only the auditor, decrypting all memos, finds the real reports among dummies. This mirrors CTR practice (bank sees everything, files only above threshold) and is the detail that prevents the disclosure mechanism itself becoming a leak.

### 7.5 What observers see

Per spend: nullifiers (unlinkable PRF outputs), fresh commitments, a memo blob, a proof. Identical shape for every spend. Per person, ever: one enrollment event. The auditor additionally learns: pseudonymous records `(person_id, subtotal, day)` for above-threshold days only — the exact analog of a CTR file, with `person_id` a scoped hash it cannot invert; legal identification requires compelling the person, per policy (reveal map is policy-parameterized, CAP-style).

### 7.6 Concurrency

One tally chain per person serializes that person's spends (wallet handles ordering). Acceptable for v1; noted in discussion.

## 8. Security properties (paper definitions, informal statements)

1. **Limit soundness game:** adversary controlling q enrolled credentials and any number of accounts cannot get the pool to accept spends exceeding q·T in one day without ≥1 memo decrypting to a valid disclosure record. Reduction to: SNARK soundness, Merkle/nullifier binding, credential-layer soundness.
2. **Unlinkability game:** adversary (full chain view, minus auditor key) cannot distinguish which of two enrolled persons authorized a challenge spend, advantage negl. Reduction to: hiding commitments, PRF security, ciphertext indistinguishability of memos.
3. **Disclosure correctness:** every accepted spend with `s_new > T` yields a memo decrypting under APK to the true `(person_id, s_new, d_now)`.

Objections engaged in the discussion section: Vitalik's zkid critique (one-per-person collapses pseudonymity → answered: per-person state exists but is cryptographically unlinkable; the person holds N unlinkable accounts, not one pseudonym); Friolo et al. (persistent payer state as coercion surface → answered: state is self-custodied, disclosure is threshold-gated and pseudonymous; residual risk acknowledged).

## 9. Implementation plan (PoC = paper's evaluation section)

- **Language:** Noir (matches zkPassport's stack; composable later). Barretenberg proving backend.
- **Scope:** minimal shielded pool in a TypeScript harness — Poseidon commitments, Merkle tree, nullifier sets, the enrollment + spend circuits, memo encryption. No production-pool integration (months, not weeks).
- **Credential layer:** mocked behind the §7.1 interface (pre-verified `person_secret` commitments); zkPassport's published proving costs cited for the end-to-end estimate. Disclosed plainly in the paper.
- **Benchmarks reported:** constraint counts per circuit, proving time, verification time, memo overhead; comparison table against PRCash/UTT/Platypus/PEReDi/Paxpay characteristics (from prior-art sweeps, see `docs/research/prior-art-notes.md`).
- **Stretch (only if time remains):** Solidity verifier on a testnet for gas numbers.

## 10. Paper skeleton

Abstract → 1 Introduction (registry-vs-privacy dilemma, legal mandates) → 2 Related work (three-layer map from sweeps: identity / accounting / enforcement — every cell occupied except ours) → 3 Model & definitions (§8) → 4 Construction (§7) → 5 Security analysis → 6 Implementation & evaluation (§9) → 7 Discussion (non-claims §4, objections §8, deployment, extensions) → 8 Conclusion.

**Venue strategy:** ePrint/arXiv the moment the draft is respectable (priority timestamp — scoop risk is real and named: SyRA authors, PoP-foundations group, rate-limited-token line, World/human.tech industry track). Then FC or AFT; deadlines to be checked at submission time. Optional: one cryptographer collaborator for a proofs pass pre-venue.

## 11. Extensions (explicitly not v1)

Rolling bucket-vector windows (closes epoch-straddling; the Idea-1 salvage, slots into the tally note as a vector of day-buckets); threshold auditor committee; receive-side aggregation; credential revocation lists; additional credential types (Aadhaar, eIDAS); cross-document dedup.

## 12. Resolved policy knobs

T = 10,000 currency units/day (CTR analog); day boundary = UTC business day; disclosure record = `(person_id, subtotal, day)`; document-bound identity (§7.1).
