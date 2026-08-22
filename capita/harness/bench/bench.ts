/**
 * Task 12 benchmark: for each circuit, constraint count, witness-generation
 * time, proving time, verification time, proof size, and -- for spend, the
 * only circuit with one -- the uniform disclosure memo's public overhead.
 * Reuses `src/prove.ts`'s real prove()/verify() (Task 11) rather than
 * reimplementing proof generation, and the same live-pool witness
 * construction `bench/spend-bench.ts` already established: witnesses come
 * from a real enroll/deposit/spend flow, not a synthetic one, so the timed
 * operations are the ones a real transaction performs.
 *
 * Distinct from spend-bench.ts, which exists to produce the paper's
 * below/above-threshold uniformity comparison specifically. This script's
 * job is the plan's Task 12 table: one row per circuit, with witness
 * generation broken out as its own measurement.
 *
 * Run: npx tsx bench/bench.ts
 */
import { fileURLToPath } from "node:url";
import { compile, execute, nargoInfo, prove, verify, closeProver } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { ownerPk } from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";
import { T_THRESHOLD } from "../src/constants.js";
import { GRUMPKIN_ORDER } from "../src/grumpkin.js";
import { encrypt, keygen, type Limbs } from "../src/elgamal.js";

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);

const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;
const DAY = 20260822n;
const ASK = 271828n;
const APK = keygen(ASK);
// The plan asks for a median of 5, distinct from spend-bench.ts's default
// of 10 -- these are separate scripts measuring separate things.
const REPS = 5;

/** Median, not mean: proving is jitter-prone under background load. */
function median(samples: number[]): number {
  const s = [...samples].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

interface Row {
  circuit: string;
  acirOpcodes: number;
  witnessGenMs: number;
  proveMs: number;
  verifyMs: number;
  proofBytes: number;
  memoOverheadBytes: number | null;
}

/** Field elements are always 32 bytes in bb.js's fixed-width encoding. */
const FIELD_BYTES = 32;

async function benchEnrollment(): Promise<Row> {
  const info = nargoInfo(ENROLLMENT_DIR);
  const inputs = { person_secret: toHex(9001n), r_t: toHex(71n), d_now: toHex(DAY) };

  const witnessMs: number[] = [];
  let witness!: Uint8Array;
  for (let i = 0; i < REPS; i++) {
    const t0 = performance.now();
    const result = await execute(ENROLLMENT_DIR, inputs);
    witnessMs.push(performance.now() - t0);
    witness = result.witness;
  }

  // Warm-up outside the timed loop: the first proof pays for one-time SRS
  // loading and WASM warm-up, a process cost rather than a per-proof one.
  await prove(ENROLLMENT_DIR, witness);

  const proveMs: number[] = [];
  const verifyMs: number[] = [];
  let proofBytes = 0;
  for (let i = 0; i < REPS; i++) {
    const t0 = performance.now();
    const { proof, publicInputs } = await prove(ENROLLMENT_DIR, witness);
    proveMs.push(performance.now() - t0);
    proofBytes = proof.length;

    const t1 = performance.now();
    const ok = await verify(ENROLLMENT_DIR, proof, publicInputs);
    verifyMs.push(performance.now() - t1);
    if (!ok) throw new Error("enrollment proof failed to verify during benchmark");
  }

  return {
    circuit: "enrollment",
    acirOpcodes: info.acirOpcodes,
    witnessGenMs: median(witnessMs),
    proveMs: median(proveMs),
    verifyMs: median(verifyMs),
    proofBytes,
    memoOverheadBytes: null, // enrollment carries no disclosure memo
  };
}

async function benchSpend(): Promise<Row> {
  const info = nargoInfo(SPEND_DIR);

  // Live pool state, exactly as bench/spend-bench.ts builds it: a real
  // enroll and a real deposit, so the spend proves membership from an
  // opening the pool actually holds rather than a fabricated one.
  const pool = new Pool(DAY);
  const { returnValue: enrollReturn } = await execute(ENROLLMENT_DIR, {
    person_secret: toHex(9002n),
    r_t: toHex(71n),
    d_now: toHex(DAY),
  });
  const [e, cT] = (enrollReturn as [string, string]).map(BigInt);
  const enrollment: EnrollOutput = { E: e, cT, dNow: DAY };
  await pool.enroll(enrollment);

  const ownerSk = 1111n;
  const pk = await ownerPk(ownerSk);
  const recipientPk = await ownerPk(2222n);
  const { index } = await pool.deposit(20_000n, pk);
  const root = pool.tree.root();

  const v1 = 6_000n;
  const rEnc = 501n;
  const msg: Limbs = [0n, 0n, 0n, 0n]; // below T -- dummy memo
  const memo = await encrypt(msg, APK, rEnc);
  const rEncCanonical = ((rEnc % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;

  const inputs = {
    person_secret: toHex(9002n),
    v_in: toHex(20_000n),
    owner_sk: toHex(ownerSk),
    r_in: toHex(BigInt(index)),
    path_in_siblings: pool.tree.path(index).siblings.map(toHex),
    path_in_indices: pool.tree.path(index).indices.map((bit) => bit === 1),
    v1: toHex(v1),
    pk1: toHex(recipientPk),
    r1: toHex(333n),
    v2: toHex(20_000n - v1),
    r2: toHex(444n),
    s_old: toHex(0n),
    d_old: toHex(DAY),
    r_t: toHex(71n),
    path_t_siblings: pool.tree.path(0).siblings.map(toHex),
    path_t_indices: pool.tree.path(0).indices.map((bit) => bit === 1),
    r_t_new: toHex(555n),
    r_enc_lo: toHex(rEncCanonical & MASK_128),
    r_enc_hi: toHex(rEncCanonical >> 128n),
    root: toHex(root),
    d_now: toHex(DAY),
    t_threshold: toHex(T_THRESHOLD),
    apk_x: toHex(APK.x),
    apk_y: toHex(APK.y),
    c1: [toHex(memo.c1.x), toHex(memo.c1.y)],
    ct: memo.ct.map(toHex),
  };

  const witnessMs: number[] = [];
  let witness!: Uint8Array;
  for (let i = 0; i < REPS; i++) {
    const t0 = performance.now();
    const result = await execute(SPEND_DIR, inputs);
    witnessMs.push(performance.now() - t0);
    witness = result.witness;
  }

  await prove(SPEND_DIR, witness); // warm-up, as above

  const proveMs: number[] = [];
  const verifyMs: number[] = [];
  let proofBytes = 0;
  for (let i = 0; i < REPS; i++) {
    const t0 = performance.now();
    const { proof, publicInputs } = await prove(SPEND_DIR, witness);
    proveMs.push(performance.now() - t0);
    proofBytes = proof.length;

    const t1 = performance.now();
    const ok = await verify(SPEND_DIR, proof, publicInputs);
    verifyMs.push(performance.now() - t1);
    if (!ok) throw new Error("spend proof failed to verify during benchmark");
  }

  return {
    circuit: "spend",
    acirOpcodes: info.acirOpcodes,
    witnessGenMs: median(witnessMs),
    proveMs: median(proveMs),
    verifyMs: median(verifyMs),
    proofBytes,
    // c1 (2 field elements) + ct (4 field elements): the disclosure memo's
    // entire public footprint, over and above what a spend circuit with no
    // privacy mechanism would need to publish at all. Every spend carries
    // this whether the memo is a dummy or a real report -- that uniformity
    // is the point (see spend-bench.ts), so one figure covers both.
    memoOverheadBytes: 6 * FIELD_BYTES,
  };
}

function toMarkdownTable(rows: Row[]): string {
  const header =
    "| Circuit | ACIR opcodes | Witness gen | Prove | Verify | Proof size | Memo overhead |\n" +
    "|---|---:|---:|---:|---:|---:|---:|\n";
  const body = rows
    .map((r) => {
      const memo = r.memoOverheadBytes === null ? "n/a" : `${r.memoOverheadBytes} B`;
      return (
        `| ${r.circuit} | ${r.acirOpcodes} | ${r.witnessGenMs.toFixed(2)} ms | ` +
        `${r.proveMs.toFixed(1)} ms | ${r.verifyMs.toFixed(2)} ms | ${r.proofBytes} B | ${memo} |`
      );
    })
    .join("\n");
  return header + body + "\n";
}

async function main() {
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);

  const rows = [await benchEnrollment(), await benchSpend()];

  console.log(toMarkdownTable(rows));

  await closeProver();
  await closePoseidon();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
