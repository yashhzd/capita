# Capita

**Person-bound spending limits for shielded payments, without a registry.**

A research prototype exploring one question: can a regulatory volume limit be enforced *per unique human*, across any number of unlinkable accounts, in a permissionless private payment system, with no registration authority, no central identity database, and without the per-person state becoming a tracking tag?

> **Status: work in progress (research code).** 8 of 14 planned tasks complete. The circuits and harness are tested and green, but the credential layer is mocked and real proof generation is not wired up yet. See [Current status](#current-status) for exactly what does and does not work. Not audited. Do not use with real money.

## The problem

Financial regulation in two major jurisdictions already requires something that no private payment system can do.

**United States.** [31 CFR 1010.313(b)](https://www.ecfr.gov/current/title-31/section-1010.313) requires a bank to *aggregate* currency transactions by the same person across all of that person's accounts within one business day, and file a report if the total crosses the threshold. The rule is deliberately per-person, not per-account, precisely so that splitting money across accounts does not evade it. FinCEN's December 2020 proposal (85 FR 83840) tried to port the same rule to cryptocurrency.

**European Union.** The digital euro proposal (Art. 35(8)) mandates per-person holding limits that hold *across all payment service providers*. The ECB's implementation is a central registry of user identifiers, the "Single Access Point." The EDPB/EDPS [Joint Opinion 02/2023](https://www.edpb.europa.eu/) objected to it on proportionality grounds and stated that decentralized storage of those identifiers is technically feasible. No one has designed that system.

So there is a real, written, in-force requirement to enforce limits per human. And there are two families of systems, neither of which meets it:

| | Enforces limits per person | Permissionless | No identity database |
|---|---|---|---|
| Banks, digital euro (SAP) | yes | no | no |
| Academic private-payment systems with limits (UTT, PRCash, PEReDi, Platypus) | yes | no | no, a registrar holds the user list |
| Deployed shielded pools (Zcash, Railgun, Privacy Pools, Aztec) | no, limits bind to accounts | yes | yes |
| **Capita** | **yes** | **yes** | **yes** |

Every system in the first two rows buys person-binding by having *someone* keep a list of who is enrolled. Every system in the third row stays permissionless by giving up on person-binding, which means limits bind to accounts, and accounts are free to create. Open ten wallets, get ten times the limit.

The empty cell is the whole project: **person-bound limits, permissionless, no registry.**

### Why this is hard

The naive fix is obvious and wrong. Give each person a persistent identifier, attach a running total to it, check the total before every spend. That works, and it also destroys the privacy you were trying to keep: the identifier appears on every transaction that person ever makes, and it links all of them together. You have built a supercookie and stapled it to the payment layer.

So the actual technical problem is: **maintain per-person cumulative state that is unlinkable, even to the party maintaining it, even across the person's own transactions.** The state has to be simultaneously persistent (so the limit means something) and untraceable (so it is not a tag).

## What Capita builds

Four pieces.

**1. Identity comes from a passport, not from a registrar.** Every ICAO e-passport carries an NFC chip whose data is signed by the issuing government. A zero-knowledge circuit can verify that signature without revealing the passport. This is established work (zk-creds, zkPassport, Anon Aadhaar); Capita consumes it rather than rebuilding it. From the passport data the holder derives

```
person_secret = H(passport_data)
person_id     = Poseidon2(person_secret, APP_SCOPE)
```

`person_id` is scoped to this system, so the identifier here is unlinkable to the identifier the same passport produces in any other application. Nobody else ever learns either value. There is no enrollment server, because there is nothing to enroll *with*: the government already signed the credential, years ago, at a passport office.

**2. The running total is itself a shielded note.** This is the core design decision. Rather than putting per-person state in a side structure (which is what makes it a supercookie), Capita puts it in the *same commitment Merkle tree* as the money. A **tally note** commits to

```
tally_commit = Poseidon2(DOMAIN_TALLY, person_id, subtotal, day, randomness)
```

and lives in the tree next to ordinary payment notes, indistinguishable from them. It therefore inherits the pool's existing unlinkability for free: a hiding commitment reveals nothing, and it is spent the same way money is spent, by revealing a nullifier rather than a pointer. Consecutive tally notes belonging to the same person cannot be linked to each other any more than consecutive payment notes can.

**3. Every spend must consume and replace the person's tally note.** The spend circuit proves, in a single proof:

- **Payment validity.** Input notes exist in the tree, the prover owns them, value is conserved, output commitments are well formed. Standard shielded-pool machinery.
- **Tally consume.** The prover supplies `person_secret` as a witness. The circuit *re-derives* `person_id` from it, then proves a tally note carrying exactly that `person_id` exists in the tree, and reveals its nullifier. Reusing an old tally note is a double-spend and the nullifier set rejects it. Skipping the tally is impossible because the circuit requires one for every spend. Forging a tally note for someone else requires their `person_secret`, which requires their passport.
- **Tally update.** If the day rolled over, the subtotal resets to this spend's amount; otherwise it accumulates. The new tally note commits to `(person_id, new_subtotal, today)`.

Because there is exactly one tally chain per person, and every spend from every wallet they own must advance that one chain, opening more accounts does not help. The limit follows the human.

**4. Uniform disclosure memos.** Above the threshold, the spend must produce a disclosure record encrypted to the auditor. The subtlety is that if only above-threshold spends carried a memo, the memo's *presence* would announce "this person just crossed the limit," and the compliance mechanism would itself become the privacy leak.

So **every** spend carries an identically shaped ciphertext, always the same size, always the same structure: a real record `(person_id, subtotal, day)` when over threshold, a fixed dummy when under. Correct encryption is proven inside the circuit, so a prover cannot substitute garbage. On-chain observers see one indistinguishable blob per transaction and cannot tell crossings from ordinary payments. The auditor decrypts everything and finds the real reports among the dummies.

This mirrors how a bank actually works: it sees every transaction and files a report only on the ones above the line.

### What an observer sees

Per spend: nullifiers (unlinkable pseudorandom outputs), fresh commitments, one memo blob, one proof. Identical shape every time. Per person, for their entire life in the system: a single enrollment event.

The auditor additionally learns pseudonymous records `(person_id, subtotal, day)` for above-threshold days only. `person_id` is a scoped hash it cannot invert, so this is the exact analog of a filed currency transaction report: it identifies a limit crossing, and turning that into a legal identity requires going to the person, by whatever process policy demands.

## What is new here, and what is not

Research code deserves an honest boundary, so this is stated up front and repeated in the paper.

**Not claimed as novel:**

- **Threshold-triggered disclosure.** Prior art is dense and goes back to at least 2006: CHL e-tokens, GGM16, PRCash, and especially Espresso's CAP, which has enforced `tpk = ⊥ ∨ b_threshold = 1 ∨ memo = Enc_tpk(record)` in-circuit in deployed code since 2022. Capita cites and extends this, moving the trigger from per-transaction to cumulative-per-person.
- **The passport credential layer.** zk-creds (IEEE S&P 2023) and the zkPassport/Self/Anon Aadhaar ecosystem already do this. Consumed, not rebuilt.
- **Unlinkable value accumulation.** BBA+ and updatable anonymous credentials accumulate values across unlinkable sessions. They are key-bound, not person-bound, so one human can open many.

**The claim is the composition:** per-person *cumulative amount* limits, in a permissionless shielded pool, with self-sovereign personhood and no registrar, where the per-person state is pool-native and therefore unlinkable. Each of the three layers exists in isolation. Three independent prior-art sweeps found no work occupying the intersection. Notes and citations: [`docs/research/prior-art-notes.md`](docs/research/prior-art-notes.md).

**Known limits, not solved:**

- **Multiple citizenship.** Two passports means two limit slots, so `2T`. Bounded and acknowledged. No personhood system solves this.
- **Willing human mules.** A person routing spends through another consenting person's allowance is conspiracy, addressed by law rather than cryptography. The system still bounds total flow to `q·T` for `q` participating humans, which is stated as a property rather than hidden as a defect.
- **Stolen or coerced passports, and state-level credential forgery.** The trust root is government signing keys, the same root every border crossing relies on.
- **Concurrency.** One tally chain per person serializes that person's spends. Fine for a prototype, a real limitation for deployment.
- **Enrollment metadata.** Enrollment is one opaque event, but the fact and time of it are visible.
- **Receive-side aggregation.** v1 tracks the spend side only.

## Repository layout

```
capita/
  circuits/        Noir circuits
    common/        shared library: Poseidon2 sponge, commitments,
                   nullifiers, Merkle verification, hash-ElGamal
    enrollment/    one-time per-person enrollment
    spend/         the core circuit: payment + tally + disclosure
    consistency/   probe circuit pinning TS and Noir agreement
  harness/         TypeScript reference implementation and test suite
    src/           field arithmetic, Poseidon2, Merkle tree, Grumpkin,
                   ElGamal, notes, pool state machine, auditor
    tests/         vitest suites
docs/
  spec/            full design specification
  plan/            implementation plan
  research/        prior-art map and legal anchors
```

The TypeScript harness is not a client for the circuits, it is an independent second implementation of the same protocol. A consistency circuit and test suite pin the two against each other, so a mistake in one shows up as a disagreement rather than as silence.

## Design details

The protocol constants and commitment formulas are authoritative in [`docs/spec/2026-08-02-person-bound-limits-design.md`](docs/spec/2026-08-02-person-bound-limits-design.md) §7.2 and are used identically in both implementations:

```
person_id      = Poseidon2([person_secret, APP_SCOPE])
owner_pk       = Poseidon2([owner_sk])
payment_commit = Poseidon2([DOMAIN_PAYMENT, value, owner_pk, r])
tally_commit   = Poseidon2([DOMAIN_TALLY, person_id, subtotal, day, r])
enroll_null    = Poseidon2([DOMAIN_ENROLL, person_id])
note_null      = Poseidon2([DOMAIN_NULLIFIER, secret, commitment])
```

Field is the BN254 scalar field. Disclosure memos are hash-ElGamal over the embedded Grumpkin curve, computed in-circuit so correctness is enforced by the proof rather than trusted. Threshold `T = 10,000` units per UTC business day, matching the CTR analog. Merkle depth 16 for the prototype.

Distinct domain tags on every hash keep the note types from colliding: without them, a payment note could be reinterpreted as a tally note.

### A note on testing method

Soundness constraints are held to a specific bar: **every constraint that prevents an attack has a test that fails when that constraint is deleted.** Several real holes were caught this way, including an unpinned range check that allowed a negative output value, which both minted money and *decreased* the tally, a direct limit evasion.

That bar has a blind spot worth documenting, because it cost real time to find. Noir silently compiles away range checks whose witness feeds a blackbox operation, so two `assert_max_bit_size` calls emitted zero constraints while looking perfectly correct in the source. Deleting them changed nothing, because there was nothing to delete. A "delete it and watch a test fail" methodology cannot detect a constraint that was never there. The answer, in `harness/src/prove.ts` and its test, is to inspect the compiled ACIR directly and assert that every scalar witness feeding the multi-scalar multiplication has its own range opcode attached.

## Running it

Requires Node 22 and the Noir toolchain, pinned to `nargo 1.0.0-beta.22` and `bb 5.0.0-nightly.20260522` (the version pairing is not arbitrary; see [`capita/README.md`](capita/README.md) for why).

```bash
# circuit tests
cd capita/circuits/common     && nargo test
cd capita/circuits/enrollment && nargo test
cd capita/circuits/spend      && nargo test

# harness and integration tests
cd capita/harness && npm install && npx vitest run
```

## Current status

Green as of the latest commit: **79 tests passing**, 36 circuit tests (`nargo test`) and 43 harness tests (vitest).

Working:

- Poseidon2 hashing matched between the TypeScript harness and Noir across arities
- incremental Merkle tree, nullifier and enrollment sets, pool acceptance state machine
- Grumpkin curve operations and hash-ElGamal encryption, in both implementations
- enrollment circuit, with duplicate-enrollment rejection
- spend circuit: payment validity, tally consume and update, business-day reset
- threshold branch with uniform disclosure memos, including in-circuit encryption correctness

Not done yet:

- **Real proof generation.** Circuits are verified by constraint satisfaction through `nargo test`; the UltraHonk prove and verify path is still stubbed out. This is the next substantial piece of work.
- **The credential layer is mocked.** The prototype takes a pre-verified `person_secret` behind the interface in spec §7.1 rather than parsing and verifying a real passport. Published zkPassport proving costs will be cited for the end-to-end estimate. This is disclosed plainly in the paper too, since it is the difference between "the accounting works" and "the whole thing works."
- End-to-end scenario walkthrough, benchmarks, and the paper draft.

## Paper

The prototype is the evaluation section of a paper in progress. Target is an ePrint preprint first, for the priority timestamp, then a venue such as Financial Cryptography or AFT. The design specification and prior-art map in `docs/` are the working drafts of the construction and related-work sections.

## License

Not yet chosen. Until one is added, all rights reserved.
