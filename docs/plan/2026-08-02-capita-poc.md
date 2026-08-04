# Capita Protocol PoC Implementation Plan

> Implement this plan one task at a time. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Capita Protocol PoC — a minimal shielded pool with person-bound tally notes (spec: `docs/spec/2026-08-02-person-bound-limits-design.md`) — plus benchmark results and a seeded paper draft.

**Architecture:** Noir circuits (enrollment, spend) over a BN254 shielded pool simulated in a TypeScript harness (Poseidon2 commitments, incremental Merkle tree, nullifier/enrollment sets). Disclosure memos are hash-ElGamal over the embedded Grumpkin curve, computed in-circuit so correctness is enforced by the proof. Credential layer is mocked behind the spec §7.1 interface.

**Tech Stack:** Noir (nargo) + barretenberg (`@aztec/bb.js`, UltraHonk), `@noir-lang/noir_js`, TypeScript + vitest, Node 22.

## Global Constraints

- Field: BN254 scalar field, `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`. All TS field math is `bigint mod p`.
- Amounts and subtotals: `u64` range-checked. Days: `u32`. Threshold `T = 10000` (spec §12). Merkle depth: 16 (PoC).
- Domain tags: `DOMAIN_PAYMENT=1, DOMAIN_TALLY=2, DOMAIN_ENROLL=3, DOMAIN_NULLIFIER=4`. `APP_SCOPE = 0xCA717A` (placeholder constant; any fixed field element).
- Commitments (spec §7.2, used identically in TS and Noir):
  - `person_id = P2([person_secret, APP_SCOPE])`
  - payment `C = P2([DOMAIN_PAYMENT, v, owner_pk, r])`, `owner_pk = P2([owner_sk])`
  - tally `C_t = P2([DOMAIN_TALLY, person_id, s, d, r])`
  - enrollment nullifier `E = P2([DOMAIN_ENROLL, person_id])`
  - note nullifier `N = P2([DOMAIN_NULLIFIER, secret, C])` (secret = `owner_sk` for payment, `person_secret` for tally)
- Spend arity: 1 payment input, 2 outputs (recipient + self-change). Tally counts `v1` (recipient output) only — self-change never counts; self-transfers burn allowance (accepted PoC simplification, note in paper).
- Git: work on branch `feat/capita-poc`. Never commit to `main`. Commit messages `type(scope): description`.
- Tests: deterministic (fixed seeds), no network access. `nargo test` for circuit logic, vitest for TS + integration.
- Noir stdlib API drift is expected (embedded-curve and poseidon2 call signatures): Task 5's TS↔Noir consistency test is the source of truth — if names differ from this plan, adapt the call sites, never the protocol constants.

### Repository layout (created across tasks)

```
capita/
  circuits/common/      # Noir lib: commitments, nullifiers, merkle, elgamal
  circuits/enrollment/  # Noir bin
  circuits/spend/       # Noir bin
  harness/src/          # field.ts, poseidon.ts, merkle.ts, grumpkin.ts, elgamal.ts,
                        # notes.ts, pool.ts, auditor.ts, prove.ts, constants.ts
  harness/tests/        # vitest suites
  harness/bench/        # bench.ts → RESULTS.md
paper/draft.md          # seeded paper draft
```

### Task 1: Scaffold and toolchain verification

**Files:**
- Create: `capita/harness/package.json`, `capita/harness/tsconfig.json`, `capita/harness/src/constants.ts`, `capita/harness/tests/toolchain.test.ts`, `.gitignore`

**Interfaces:**
- Produces: `constants.ts` exporting `P: bigint`, `DOMAIN_PAYMENT|TALLY|ENROLL|NULLIFIER: bigint`, `APP_SCOPE: bigint`, `T_THRESHOLD = 10000n`, `MERKLE_DEPTH = 16`.

- [ ] **Step 1: Branch setup**

```bash
cd "/Users/yashhzd/Desktop/zk proof work "
git branch main            # main now exists at the spec commit; never commit on it
git checkout -b feat/capita-poc
```

- [ ] **Step 2: Install toolchain, record versions**

```bash
noirup && bbup            # install if missing: curl -L noirup.dev | bash ; curl -L bbup.dev | bash
nargo --version           # record output in README.md "Toolchain" section
mkdir -p capita/harness/src capita/harness/tests capita/harness/bench
cd capita/harness && npm init -y && npm i -D typescript vitest tsx && npm i @aztec/bb.js @noir-lang/noir_js
```

`package.json` gets `"type": "module"` and `"scripts": {"test": "vitest run"}`. `tsconfig.json`: `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true,"skipLibCheck":true}}`. Root `.gitignore`: `node_modules/`, `capita/circuits/*/target/`.

- [ ] **Step 3: Write failing toolchain test**

`capita/harness/tests/toolchain.test.ts`:
```ts
import { test, expect } from "vitest";
import { poseidon2Hash } from "@aztec/bb.js";
import { P } from "../src/constants.js";

test("poseidon2 is available, deterministic, field-bounded", async () => {
  const a = (await poseidon2Hash([1n, 2n])).toBigInt();
  const b = (await poseidon2Hash([1n, 2n])).toBigInt();
  const c = (await poseidon2Hash([2n, 1n])).toBigInt();
  expect(a).toBe(b);
  expect(a).not.toBe(c);
  expect(a < P).toBe(true);
});
```
(If the installed bb.js exposes `poseidon2Hash` synchronously or under `BarretenbergSync`, adapt the import in `poseidon.ts` wrapper come Task 2 — this test locks behavior, not API shape.)

- [ ] **Step 4: Write `constants.ts`, run test to pass**

```ts
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DOMAIN_PAYMENT = 1n, DOMAIN_TALLY = 2n, DOMAIN_ENROLL = 3n, DOMAIN_NULLIFIER = 4n;
export const APP_SCOPE = 0xca717an;
export const T_THRESHOLD = 10000n;
export const MERKLE_DEPTH = 16;
```
Run: `npx vitest run tests/toolchain.test.ts` → PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore(harness): scaffold TypeScript harness and toolchain check"
```

### Task 2: Poseidon wrapper and incremental Merkle tree

**Files:**
- Create: `capita/harness/src/poseidon.ts`, `capita/harness/src/merkle.ts`, `capita/harness/tests/merkle.test.ts`

**Interfaces:**
- Produces: `p2(inputs: bigint[]): Promise<bigint>`; `class MerkleTree { insert(leaf: bigint): Promise<number>; root(): bigint; path(index: number): {siblings: bigint[]; indices: number[]}; static async verify(root: bigint, leaf: bigint, path: Path): Promise<boolean> }`. Empty leaf = `0n`; node = `p2([left, right])`; depth from `MERKLE_DEPTH`.

- [ ] **Step 1: Write failing tests**

```ts
import { test, expect } from "vitest";
import { MerkleTree } from "../src/merkle.js";
import { p2 } from "../src/poseidon.js";

test("insert changes root; path verifies; wrong leaf fails", async () => {
  const t = new MerkleTree();
  const r0 = t.root();
  const i = await t.insert(42n);
  expect(t.root()).not.toBe(r0);
  const path = t.path(i);
  expect(await MerkleTree.verify(t.root(), 42n, path)).toBe(true);
  expect(await MerkleTree.verify(t.root(), 43n, path)).toBe(false);
});

test("two inserts, both paths verify against same root", async () => {
  const t = new MerkleTree();
  const i1 = await t.insert(7n), i2 = await t.insert(9n);
  expect(await MerkleTree.verify(t.root(), 7n, t.path(i1))).toBe(true);
  expect(await MerkleTree.verify(t.root(), 9n, t.path(i2))).toBe(true);
});
```
Run → FAIL (modules missing).

- [ ] **Step 2: Implement `poseidon.ts` and `merkle.ts`**

`poseidon.ts`: thin wrapper exporting `p2` over bb.js's poseidon2 (normalize Fr→bigint). `merkle.ts`: classic incremental tree — store `zeros[d]` (precomputed zero-subtree hashes), `filledSubtrees[d]`, `leaves[]`; `insert` walks depth updating; `path` recomputes siblings from stored leaves (PoC: rebuild level lists on demand — O(n·d) is fine); `verify` folds leaf up with `indices[k] ? p2([sib, cur]) : p2([cur, sib])`.

- [ ] **Step 3: Run tests** → PASS.

- [ ] **Step 4: Commit** `feat(harness): poseidon2 wrapper and incremental merkle tree`

### Task 3: Grumpkin curve and hash-ElGamal

**Files:**
- Create: `capita/harness/src/grumpkin.ts`, `capita/harness/src/elgamal.ts`, `capita/harness/tests/elgamal.test.ts`

**Interfaces:**
- Produces: `grumpkin.ts`: `type Pt = {x: bigint; y: bigint; inf: boolean}`; `G: Pt` (generator `x=1`, even-`y` root of `1-17`); `mul(k: bigint, P: Pt): Pt`; `add(P: Pt, Q: Pt): Pt`; curve `y² = x³ − 17` over base field `P` (Tonelli–Shanks sqrt included, ~15 lines).
- Produces: `elgamal.ts`: `keygen(sk: bigint): Pt`; `encrypt(msg: bigint[4], apk: Pt, rEnc: bigint): Promise<{c1: Pt; ct: bigint[4]}>` with `ct[i] = (msg[i] + p2([S.x, S.y, i])) mod P`, `S = mul(rEnc, apk)`, `c1 = mul(rEnc, G)`; `decrypt(memo, ask): Promise<bigint[4]>` via `S = mul(ask, c1)`.
- Note: generator must match the circuit's embedded-curve generator; Task 5's consistency test reconciles (if mismatch, adopt circuit coordinates into `G` and re-run — protocol unaffected).

- [ ] **Step 1: Write failing tests**

```ts
test("elgamal roundtrip", async () => {
  const ask = 123456789n, apk = keygen(ask);
  const msg: [bigint,bigint,bigint,bigint] = [1n, 999n, 10500n, 20666n];
  const memo = await encrypt(msg, apk, 42n);
  expect(await decrypt(memo, ask)).toEqual(msg);
});
test("wrong key garbles", async () => {
  const memo = await encrypt([1n,2n,3n,4n], keygen(5n), 42n);
  expect(await decrypt(memo, 6n)).not.toEqual([1n,2n,3n,4n]);
});
test("curve sanity: G on curve, mul(2,G)=add(G,G)", () => {
  expect(((G.y*G.y) % P)).toBe((((G.x**3n % P) - 17n % P) + P) % P);
  expect(mul(2n, G)).toEqual(add(G, G));
});
```
Run → FAIL.

- [ ] **Step 2: Implement** (short-Weierstrass double-and-add with bigint modular inverse via extended Euclid; Tonelli–Shanks for the generator y; hash-pads from `p2`).

- [ ] **Step 3: Run tests** → PASS.

- [ ] **Step 4: Commit** `feat(harness): grumpkin ops and hash-elgamal memo encryption`

### Task 4: Notes, identity, nullifiers

**Files:**
- Create: `capita/harness/src/notes.ts`, `capita/harness/tests/notes.test.ts`

**Interfaces:**
- Produces (all `Promise<bigint>` unless noted, formulas from Global Constraints): `personId(personSecret)`, `enrollNullifier(personId)`, `ownerPk(ownerSk)`, `paymentCommit(v, ownerPk, r)`, `tallyCommit(personId, s, d, r)`, `noteNullifier(secret, commit)`.

- [ ] **Step 1: Failing tests** — determinism; domain separation (`paymentCommit(1n,2n,3n) ≠ tallyCommit(...)` given colliding raw inputs); `personId` differs across secrets; nullifier differs across commits.

```ts
test("domain separation", async () => {
  expect(await paymentCommit(5n, 6n, 7n)).not.toBe(await tallyCommit(5n, 6n, 7n, 0n).catch(() => 0n));
  expect(await personId(11n)).not.toBe(await personId(12n));
});
```

- [ ] **Step 2: Implement** (one-liners over `p2` with domain tags). Run → PASS.

- [ ] **Step 3: Commit** `feat(harness): note commitments, person identity, nullifiers`

### Task 5: Noir common library + TS↔Noir consistency gate

**Files:**
- Create: `capita/circuits/common/Nargo.toml`, `capita/circuits/common/src/lib.nr`, `capita/circuits/consistency/` (throwaway bin crate), `capita/harness/src/prove.ts`, `capita/harness/tests/consistency.test.ts`

**Interfaces:**
- Produces (`lib.nr`): `person_id(secret: Field) -> Field`; `payment_commit(v: Field, owner_pk: Field, r: Field) -> Field`; `tally_commit(pid: Field, s: Field, d: Field, r: Field) -> Field`; `note_nullifier(secret: Field, c: Field) -> Field`; `enroll_nullifier(pid: Field) -> Field`; `merkle_verify(leaf: Field, root: Field, siblings: [Field; 16], indices: [u1; 16])`; `elgamal_encrypt(msg: [Field; 4], apk_x: Field, apk_y: Field, r_enc: Field) -> ([Field; 2], [Field; 4])` (returns c1 then ct).
- Produces (`prove.ts`): `execute(circuitDir: string, inputs: Record<string, unknown>): Promise<{witness, returnValue}>` via noir_js against `nargo compile` artifacts; `prove/verify(circuitDir, witness)` via UltraHonk (used from Task 11).
- The consistency bin's `main` takes a probe secret/values and returns all hashes + one `elgamal_encrypt` output + the fixed-base generator point.

- [ ] **Step 1: Write `lib.nr`** using `std::hash::poseidon2` and `std::embedded_curve_ops` (adapt exact call names to installed stdlib; constants identical to `constants.ts`). Include `nargo test` unit tests inside the lib for merkle fold and domain separation.

- [ ] **Step 2: Run `nargo test`** in `circuits/common` → PASS.

- [ ] **Step 3: Consistency test (the gate).** `consistency.test.ts` executes the probe circuit via `prove.ts` and asserts every TS function (Tasks 2–4) matches circuit output on 3 fixed input sets; asserts TS `G`/`mul` reproduce the circuit's generator and `c1`. Run → reconcile until PASS (adopt circuit generator coords into `grumpkin.ts` if needed).

- [ ] **Step 4: Commit** `feat(circuits): noir common lib with cross-implementation consistency gate`

### Task 6: Enrollment circuit + pool enrollment flow

**Files:**
- Create: `capita/circuits/enrollment/{Nargo.toml,src/main.nr}`, `capita/harness/src/pool.ts` (initial), `capita/harness/tests/enroll.test.ts`

**Interfaces:**
- Circuit `main(person_secret: Field, r_t: Field, d_now: pub Field) -> pub (Field, Field)` returning `(E, C_t_genesis)`; constrains `E = enroll_nullifier(person_id(person_secret))`, `C_t = tally_commit(pid, 0, d_now, r_t)`.
- Produces (`pool.ts`): `class Pool { currentDay: bigint; tree: MerkleTree; seenNullifiers: Set<string>; seenEnrollments: Set<string>; rootHistory: Set<string>; async enroll(proofOut: {E: bigint; cT: bigint; dNow: bigint}): Promise<void>` (throws `"duplicate-enrollment"` / `"wrong-day"`), inserts `cT`, records root. }`

- [ ] **Step 1: Failing tests** — enroll succeeds and inserts genesis tally; same-secret second enroll throws `duplicate-enrollment`; different secret succeeds; `d_now ≠ pool.currentDay` throws.

- [ ] **Step 2: Implement circuit + pool.enroll; execute circuit in test via `execute()`** → PASS. (`nargo test` case inside circuit for constraint logic.)

- [ ] **Step 3: Commit** `feat(circuits): enrollment circuit and pool enrollment with duplicate rejection`

### Task 7: Spend circuit — payment validity and tally accumulation (same-day)

**Files:**
- Create: `capita/circuits/spend/{Nargo.toml,src/main.nr}` (threshold/memo arrive Task 8), `capita/harness/tests/spend-core.test.ts`
- Modify: `capita/harness/src/pool.ts` (add `deposit(v, ownerPk): Promise<{commit, index}>` — transparent mint; and `spend(publicInputs): void` checks — extended Task 9)

**Interfaces:**
- Circuit `main` witness: `person_secret, v_in, owner_sk, r_in, path_in, v1, pk1, r1, v2, r2, s_old, d_old, r_t, path_t, r_t_new`; public: `root, d_now, n_pay, n_tally, c_out1, c_out2, c_tally_new`. Constraints §7.4 items 1–3 (this task: same-day accumulation only — `assert(d_now == d_old)`; rollover generalized next task): ownership, membership ×2, conservation `v_in == v1 + v2` as u64, change to self (`c_out2` uses `owner_pk`), `s_new = s_old + v1`, new tally binds `(pid, s_new, d_now)`.

- [ ] **Step 1: `nargo test` failing cases in-circuit** — valid spend satisfies; conservation violation unsatisfiable; wrong `person_secret` (tally of another pid) unsatisfiable; stale-tally path vs fresh root unsatisfiable.

- [ ] **Step 2: Implement circuit; make `nargo test` pass.**

- [ ] **Step 3: Harness test** `spend-core.test.ts`: enroll → deposit 20000 → spend v1=6000 → execute circuit, assert returned `n_tally/c_tally_new` consistent with TS-recomputed values (`s_new=6000`). Run → PASS.

- [ ] **Step 4: Commit** `feat(circuits): spend circuit core with tally accumulation`

### Task 8: Spend circuit — day rollover, threshold branch, uniform memo

**Files:**
- Modify: `capita/circuits/spend/src/main.nr`
- Create: `capita/harness/src/auditor.ts`, `capita/harness/tests/spend-threshold.test.ts`

**Interfaces:**
- Circuit gains public inputs `t_threshold, apk_x, apk_y, c1: [Field;2], ct: [Field;4]` and witness `r_enc`. New constraints: `assert(d_now as u32 >= d_old as u32)`; `s_new = if d_now == d_old { s_old + v1 } else { v1 }`; `over: bool = (s_new as u64) > (t_threshold as u64)`; `flag = over as Field`; `msg = [flag, flag*pid, flag*s_new, flag*d_now]`; `(c1, ct) == elgamal_encrypt(msg, apk_x, apk_y, r_enc)`.
- Produces (`auditor.ts`): `async collect(memos: Memo[], ask: bigint): Promise<Disclosure[]>` — decrypts all, keeps `flag == 1n`, returns `{personId, subtotal, day}`.

- [ ] **Step 1: Failing vitest cases** — below threshold: memo decrypts to `[0,0,0,0]`; crossing (6000 then 5000, same day): second memo decrypts to `[1, pid, 11000, day]`; day rollover: 6000 day d, 5000 day d+1 → both memos dummy (subtotal reset); `auditor.collect` returns exactly the one real disclosure; memo ciphertexts for real and dummy are indistinguishable in shape (structural: same field count).

- [ ] **Step 2: Implement; run `nargo test` + vitest** → PASS.

- [ ] **Step 3: Commit** `feat(circuits): threshold branch with uniform hash-elgamal disclosure memos`

### Task 9: Pool state machine — full acceptance rules

**Files:**
- Modify: `capita/harness/src/pool.ts`
- Create: `capita/harness/tests/pool-rules.test.ts`

**Interfaces:**
- `pool.spend(pub: SpendPublicInputs): void` enforces, in order: root ∈ rootHistory (`"unknown-root"`), `d_now == currentDay` (`"wrong-day"`), `n_pay ∉ seen` and `n_tally ∉ seen` (`"double-spend"`), then admits: adds nullifiers, inserts `c_out1, c_out2, c_tally_new`, records new root. `advanceDay(): void` increments `currentDay`.
- Circuit-level verification is what makes admission sound; in unit tests the executed witness stands in for a verified proof (real proofs: Task 11).

- [ ] **Step 1: Failing tests** — replaying same spend throws `double-spend`; spending consumed tally (build second spend against old tally note) throws `double-spend` on `n_tally`; spend referencing pre-insertion root throws `unknown-root`; spend with yesterday's `d_now` after `advanceDay()` throws `wrong-day`.

- [ ] **Step 2: Implement; run** → PASS.

- [ ] **Step 3: Commit** `feat(harness): pool acceptance rules for nullifiers, roots, and day clock`

### Task 10: End-to-end scenario — the paper's walkthrough

**Files:**
- Create: `capita/harness/tests/e2e.test.ts`

**Interfaces:**
- Consumes everything; produces the narrative test the paper's §6 describes.

- [ ] **Step 1: Write the scenario test (failing only if prior tasks broke):**

1. Alice enrolls (passport-mock secret `sA`). Bob enrolls (`sB`).
2. Alice deposits 20000 into wallet A1; deposits 8000 into a second wallet A2 (different `owner_sk`, same person).
3. Alice spends 6000 from A1 (→ tally 6000, dummy memo).
4. Alice spends 5000 from A2 — **different wallet, same person**: circuit forces her single tally chain → `s_new = 11000 > T` → real disclosure. Assert auditor recovers exactly `(pid_A, 11000, d)`.
5. Bob spends 9000 → dummy memo. Assert auditor's collection contains nothing for Bob.
6. Attempt: Alice re-enrolls to reset → `duplicate-enrollment`.
7. Structural unlinkability check: assert the on-chain transcript (all public inputs recorded by the pool) contains no occurrence of `pid_A`, `pid_B`, `sA`, `sB` as field values, and that spend records are shape-identical.
8. `advanceDay()`; Alice spends 4000 → dummy memo (reset worked).

- [ ] **Step 2: Run full suite** (`nargo test` all crates + `npx vitest run`) → PASS.

- [ ] **Step 3: Commit** `test(e2e): multi-wallet person-bound threshold scenario with auditor recovery`

### Task 11: Real proving and verification (UltraHonk)

**Files:**
- Modify: `capita/harness/src/prove.ts` (activate `prove`/`verify`)
- Create: `capita/harness/tests/proving.test.ts`

- [ ] **Step 1: Failing test** — generate a real proof for one enrollment and one spend from the Task 10 scenario; `verify` returns true; tampering one public input (`c_tally_new += 1`) fails verification.

- [ ] **Step 2: Implement against bb.js UltraHonk API; run** (slow test, tag `{ timeout: 300_000 }`) → PASS. Record proof sizes.

- [ ] **Step 3: Commit** `feat(prove): ultrahonk proof generation and verification for both circuits`

### Task 12: Benchmarks and RESULTS.md

**Files:**
- Create: `capita/harness/bench/bench.ts`, `capita/RESULTS.md`

- [ ] **Step 1: Write `bench.ts`** — for each circuit: constraint count (`nargo info` parsed), witness-generation time, proving time (median of 5), verification time, proof size, memo overhead bytes. Output a markdown table.

- [ ] **Step 2: Run, paste table into `RESULTS.md`** with toolchain versions and machine spec (`sysctl -n machdep.cpu.brand_string`, RAM).

- [ ] **Step 3: Commit** `feat(bench): circuit benchmarks and results table`

### Task 13: Paper draft — skeleton and related work

**Files:**
- Create: `paper/draft.md`

- [ ] **Step 1: Seed the skeleton** with the spec's §10 section list; write the Related Work section in full prose from `docs/research/prior-art-notes.md` (three-layer map, registrar family, CAP extension statement, industry near-misses, the two surveys' silence, legal anchors) — every claim carries its citation key; build a `paper/references.md` list from the notes.

- [ ] **Step 2: Verify** — every citation in prose exists in references; every reference is cited. Commit `docs(paper): skeleton and related work draft`

### Task 14: Paper draft — core sections

**Files:**
- Modify: `paper/draft.md`

- [ ] **Step 1: Draft Introduction** (registry-vs-privacy dilemma; 31 CFR 1010.313(b); Art. 35(8) + SAP + EDPB/EDPS; contribution list from spec §1–§3), **Model & Definitions** (spec §5, §8 games in prose), **Construction** (spec §7 with a protocol figure in a fenced diagram), **Evaluation** (import RESULTS.md table; state credential-layer mock plainly per spec §9), **Discussion** (non-claims §4; Vitalik zkid + Friolo answers §8; mules economics; extensions §11).

- [ ] **Step 2: Full read-through** for spec-consistency; fix drift. Commit `docs(paper): core section drafts`

## Self-Review

**Spec coverage:** §7.1 identity → T4/T5; §7.2 notes → T4; §7.3 enrollment + duplicate-E → T6; §7.4 constraints 1–3 → T7, constraint 4 + uniform memo → T8; §7.5 observables → T10 step 7; §7.6 concurrency → serialized by tally nullifier (T9 double-spend test); §8 games → evidenced by T8/T9/T10 tests, prose in T14; §9 stack/benchmarks/mock → T1/T11/T12; §10 skeleton → T13/T14; §12 knobs → Global Constraints. Gap check: receive-side, rolling windows, threshold auditor — spec §11 non-v1, correctly absent.

**Placeholder scan:** clean — every step names exact files, formulas, or commands; API-drift points are flagged with a reconciliation gate (T5), not left vague.

**Type consistency:** commitment formulas, function names (`personId/person_id`, `tallyCommit/tally_commit`), public-input lists, and error strings match across T4–T10. `elgamal_encrypt` return order `(c1, ct)` consistent T5/T8.
